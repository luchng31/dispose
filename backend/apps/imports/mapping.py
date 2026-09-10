"""RSAS field mapping + row normalizer (Task3).

Severity mapping table (RSAS 危险程度 -> VulnTicket.Severity):

| RSAS raw (case-insensitive, stripped) | Ticket severity |
|---------------------------------------|-----------------|
| 危急, 极危, 严重, critical, crit       | 严重 (critical) |
| 高危, 高, high                         | 高 (high)       |
| 中危, 中, medium, middle               | 中 (medium)     |
| 低危, 低, low, 信息, info, informational | 低 (low)       |
| anything else / blank                 | 中 (default)    |

Normalization rules:
- ip: strip + lower; blank ip -> RowError (row quarantined, batch survives).
- port: int(...), blank/garbage -> 0.
- plugin_id: blank -> ``title-<md5(title)[:12]>`` fallback so dedup stays stable.
- cve: upper-cased first token (split on ``,;、/`` whitespace); blank -> ``NOCVE``.
- Unknown fields are collected into ``quarantined`` and never crash the batch.

DB override note (Task1 schema frozen): there is deliberately NO
``field_mapping`` table / migration in this task. Per-batch overrides can be
passed as ``overrides`` to :func:`load_field_map` and are recorded in
``ScanBatch.stats_json["field_map_version"]``. A DB-backed override table is
deferred to a later task that owns migrations.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FIELD_MAP_PATH = Path(__file__).resolve().parent / "field_map.json"
FIELD_MAP_VERSION = "2"

_CANONICAL_KEYS = (
    "ip", "port", "protocol", "service", "plugin_id", "plugin_name",
    "cve", "severity", "cvss", "description", "solution",
)

_CVE_SPLIT_RE = re.compile(r"[,;、/\s]+")

_SEVERITY_FALLBACK = {
    "危急": "严重", "极危": "严重", "严重": "严重", "critical": "严重", "crit": "严重",
    "高危": "高", "高": "高", "high": "高",
    "中危": "中", "中": "中", "medium": "中", "middle": "中",
    "低危": "低", "低": "低", "low": "低",
    "信息": "低", "info": "低", "informational": "低",
}
_DEFAULT_SEVERITY = "中"


class RowError(ValueError):
    """Single-row normalization failure. Carries the offending field name."""

    def __init__(self, row: int | str, field_name: str, message: str) -> None:
        super().__init__(message)
        self.row = row
        self.field_name = field_name
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {"row": self.row, "field": self.field_name, "message": self.message}


@dataclass(frozen=True, slots=True)
class FieldMap:
    version: str
    aliases: dict[str, list[str]]
    severity_map: dict[str, str]
    defaults: dict[str, Any]

    def canonical_key(self, raw_key: str) -> str | None:
        needle = str(raw_key).strip().lower()
        for canon, variants in self.aliases.items():
            if needle == canon or needle in {v.lower() for v in variants}:
                return canon
        return None

    def map_severity(self, raw: str) -> str:
        table = self.severity_map or _SEVERITY_FALLBACK
        text = str(raw).strip().lower()
        if text in table:
            return table[text]
        try:
            score = float(text)
        except (ValueError, TypeError):
            return _DEFAULT_SEVERITY
        if score >= 9.0:
            return "严重"
        if score >= 7.0:
            return "高"
        if score >= 4.0:
            return "中"
        return "低"


def load_field_map(overrides: dict[str, Any] | None = None) -> FieldMap:
    """Load field_map.json; optional per-batch ``overrides`` merge (no DB)."""
    data: dict[str, Any] = json.loads(FIELD_MAP_PATH.read_text(encoding="utf-8"))
    if overrides:
        for key in ("aliases", "severity_map", "defaults"):
            extra = overrides.get(key)
            if isinstance(extra, dict):
                merged: dict[str, Any] = dict(data.get(key, {}))
                merged.update(extra)
                data[key] = merged
        if "version" in overrides:
            data["version"] = overrides["version"]
    aliases: dict[str, list[str]] = {
        str(k): [str(v) for v in vs] for k, vs in data.get("aliases", {}).items()
    }
    severity: dict[str, str] = {
        str(k).lower(): str(v) for k, v in data.get("severity_map", {}).items()
    }
    return FieldMap(
        version=str(data.get("version", FIELD_MAP_VERSION)),
        aliases=aliases,
        severity_map=severity,
        defaults=dict(data.get("defaults", {})),
    )


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    ip: str
    port: int
    protocol: str
    service: str
    plugin_id: str
    plugin_name: str
    cve: str
    severity: str
    cvss: float | None
    description: str
    solution: str
    quarantined: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip, "port": self.port, "protocol": self.protocol,
            "service": self.service, "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name, "cve": self.cve,
            "severity": self.severity, "cvss": self.cvss,
            "description": self.description, "solution": self.solution,
            "quarantined": list(self.quarantined),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> NormalizedFinding:
        quarantined = data.get("quarantined", [])
        return NormalizedFinding(
            ip=str(data["ip"]), port=int(data["port"]),
            protocol=str(data.get("protocol", "tcp")),
            service=str(data.get("service", "")),
            plugin_id=str(data["plugin_id"]),
            plugin_name=str(data.get("plugin_name", "")),
            cve=str(data.get("cve", "NOCVE")),
            severity=str(data.get("severity", _DEFAULT_SEVERITY)),
            cvss=None if data.get("cvss") is None else float(data["cvss"]),
            description=str(data.get("description", "")),
            solution=str(data.get("solution", "")),
            quarantined=tuple(str(q) for q in quarantined),
        )


def _to_int_port(raw: Any) -> int:
    try:
        return int(str(raw).strip())
    except (ValueError, TypeError, AttributeError):
        return 0


def _to_float_or_none(raw: Any) -> float | None:
    if raw is None or str(raw).strip() == "":
        return None
    try:
        return float(str(raw).strip())
    except (ValueError, TypeError):
        return None


def normalize_row(
    raw: dict[str, Any],
    row_no: int | str = 0,
    field_map: FieldMap | None = None,
) -> NormalizedFinding:
    """Map one raw RSAS row to a canonical finding. Raises RowError on bad ip."""
    fmap = field_map or load_field_map()
    canon: dict[str, Any] = {}
    quarantined: list[str] = []
    for key, value in raw.items():
        hit = fmap.canonical_key(str(key))
        if hit is None:
            quarantined.append(str(key))
        elif hit not in canon:
            canon[hit] = value

    ip = str(canon.get("ip", "")).strip().lower()
    if not ip:
        raise RowError(row_no, "ip", "missing or blank ip; row quarantined")

    title = str(canon.get("plugin_name", "")).strip()
    plugin_id = str(canon.get("plugin_id", "")).strip()
    if not plugin_id:
        digest = hashlib.md5(title.encode()).hexdigest()[:12]
        plugin_id = f"title-{digest}"

    cve_raw = str(canon.get("cve", "")).strip()
    if not cve_raw:
        cve = "NOCVE"
    else:
        cve = _CVE_SPLIT_RE.split(cve_raw)[0].upper()

    return NormalizedFinding(
        ip=ip,
        port=_to_int_port(canon.get("port", 0)),
        protocol=str(canon.get("protocol", "tcp")).strip().lower() or "tcp",
        service=str(canon.get("service", "")).strip(),
        plugin_id=plugin_id,
        plugin_name=title,
        cve=cve,
        severity=fmap.map_severity(str(canon.get("severity", ""))),
        cvss=_to_float_or_none(canon.get("cvss")),
        description=str(canon.get("description", "")).strip(),
        solution=str(canon.get("solution", "")).strip(),
        quarantined=tuple(quarantined),
    )


__all__ = [
    "FIELD_MAP_PATH", "FIELD_MAP_VERSION", "FieldMap", "NormalizedFinding",
    "RowError", "load_field_map", "normalize_row",
]
