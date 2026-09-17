"""RSAS import dedup + retest reconciliation + async entry point (Task3).

Dedup: ``dedup_key = md5(ip|port|plugin_id|cve)`` (VulnTicket.dedup_key unique).

Retest reconciliation (one full rescan vs current tickets):
- new: key unseen -> create ticket (state 待分配).
- still_open: key seen + state != 已闭合 -> bump last_seen_at only.
- reopened: key seen + state == 已闭合 -> state back to 待修复,
  ``fix_evidence={reopened: True, ...}``, ``sla_due_at=None`` so Task5
  recomputes a new SLA clock.
- fixed-unverified: key NOT in rescan + state actionable
  (not 已闭合/已忽略) -> stamp
  ``fix_evidence.retest_status="fixed-unverified"`` ONLY. NEVER auto-close:
  only an operator may close (Task5); an ignored ticket keeps its explicit
  operator verdict and is never flagged.

Scope: IN-scope ZIP walk/mapping/dry-run/dedup/reconciliation. OUT-scope
auto-rescan trigger (Phase-2), CMDB dispatch (Task4), and any state change
beyond the fixed-unverified/reopened flags above.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import User
from apps.tickets.models import Severity, TicketState, VulnTicket

from .mapping import FIELD_MAP_VERSION, NormalizedFinding

RETEST_FIXED_UNVERIFIED = "fixed-unverified"

# 低危漏洞治理策略：照常生成工单（一漏一单，记录不删），但导入即转「已忽略」，
# 不进入待修复/SLA 流程；负责人仍按 IP 映射标注以便追溯。要恢复处理流程，
# 在工单详情里走「重开」。
AUTO_IGNORE_LOW_SEVERITY = True
LOW_IGNORE_REASON = "低危漏洞：按默认策略记录留存，无需修复处理"


def dedup_key_for(ip: str, port: int, plugin_id: str, cve: str) -> str:
    """Stable ticket identity: md5(ip|port|plugin_id|cve)."""
    raw = f"{ip}|{port}|{plugin_id}|{cve}"
    return hashlib.md5(raw.encode()).hexdigest()


def dedup_key_of(finding: NormalizedFinding) -> str:
    return dedup_key_for(finding.ip, finding.port, finding.plugin_id, finding.cve)


def dedupe_findings(
    findings: list[NormalizedFinding],
) -> dict[str, NormalizedFinding]:
    """Collapse same-file duplicates by dedup_key (first row wins)."""
    by_key: dict[str, NormalizedFinding] = {}
    for finding in findings:
        by_key.setdefault(dedup_key_of(finding), finding)
    return by_key


@dataclass(slots=True)
class Reconciliation:
    new_keys: list[str] = field(default_factory=list)
    still_open_keys: list[str] = field(default_factory=list)
    reopened_keys: list[str] = field(default_factory=list)
    fixed_unverified_keys: list[str] = field(default_factory=list)


def _chunked(values: list[str], size: int = 1000) -> list[list[str]]:
    return [values[i : i + size] for i in range(0, len(values), size)]


def reconcile(findings_by_key: dict[str, NormalizedFinding]) -> Reconciliation:
    """Pure-DB-read classification of one rescan. Writes nothing."""
    rec = Reconciliation()
    if findings_by_key:
        keys = list(findings_by_key)
        seen: dict[str, str] = {}
        for page in _chunked(keys):
            existing = VulnTicket.objects.filter(
                dedup_key__in=page
            ).values_list("dedup_key", "state")
            seen.update(dict(existing))
    else:
        seen = {}
    for key, state in seen.items():
        if state == TicketState.CLOSED:
            rec.reopened_keys.append(key)
        else:
            rec.still_open_keys.append(key)
    rec.new_keys = [k for k in findings_by_key if k not in seen]
    if findings_by_key:
        excluded: set[str] | None = None
        for page in _chunked(list(findings_by_key)):
            chunk = set(
                VulnTicket.objects.exclude(
                    dedup_key__in=page
                ).exclude(
                    state__in=(TicketState.CLOSED, TicketState.IGNORED)
                ).values_list("dedup_key", flat=True)
            )
            excluded = chunk if excluded is None else excluded & chunk
        rec.fixed_unverified_keys = sorted(excluded or set())
    return rec


def preview_import(
    file_hash: str,
    findings: list[NormalizedFinding],
    parse_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Dry-run preview. ZERO db writes (read-only queries + pure compute)."""
    from apps.imports.models import ScanBatch

    by_key = dedupe_findings(findings)
    rec = reconcile(by_key)
    return {
        "new": len(rec.new_keys),
        "still_open": len(rec.still_open_keys),
        "fixed_unverified": len(rec.fixed_unverified_keys),
        "reopened": len(rec.reopened_keys),
        "errors": list(parse_errors),
        "skipped": ScanBatch.objects.filter(file_hash=file_hash).exists(),
        "file_hash": file_hash,
    }


def _dispatch_and_classify(created: list[VulnTicket]) -> tuple[int, int]:
    """Auto-dispatch new tickets by IP owner map; classify states.

    Mirrors manual create: assigned -> 待修复 via the whitelisted edge
    (audit row per ticket); low severity -> 已忽略 with reason (record
    kept, no fix workflow); unassigned stays 待分配 (orphan pool).
    Returns (auto_assigned, low_ignored).
    """
    from apps.assets.dispatch import get_current_owner
    from apps.tickets.transitions import transition

    owner_cache: dict[str, User | None] = {}
    for ticket in created:
        if ticket.ip not in owner_cache:
            owner_cache[ticket.ip] = get_current_owner(ticket.ip)
        owner = owner_cache[ticket.ip]
        if owner is not None:
            ticket.assignee = owner
    VulnTicket.objects.bulk_update(
        [t for t in created if t.assignee_id is not None], ["assignee"]
    )
    auto_assigned = low_ignored = 0
    for ticket in created:
        if ticket.assignee_id is not None:
            auto_assigned += 1
        if ticket.severity == Severity.LOW and AUTO_IGNORE_LOW_SEVERITY:
            transition(
                ticket, TicketState.IGNORED, actor_role="operator",
                payload={"reason": LOW_IGNORE_REASON},
            )
            low_ignored += 1
        elif ticket.assignee_id is not None:
            transition(ticket, TicketState.PENDING_FIX, actor_role="operator")
    return auto_assigned, low_ignored


def apply_reconciliation(
    batch: object,
    findings_by_key: dict[str, NormalizedFinding],
    rec: Reconciliation,
    parse_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Apply a reconciled rescan inside one transaction. Returns stats."""
    from apps.imports.models import ScanBatch

    assert isinstance(batch, ScanBatch)
    now = timezone.now()
    with transaction.atomic():
        auto_assigned = 0
        low_ignored = 0
        if rec.new_keys:
            created = VulnTicket.objects.bulk_create(
                [
                    finding_to_ticket(findings_by_key[key], key, now, batch)
                    for key in rec.new_keys
                ],
                batch_size=1000,
            )
            auto_assigned, low_ignored = _dispatch_and_classify(created)
        if rec.still_open_keys:
            VulnTicket.objects.filter(dedup_key__in=rec.still_open_keys).update(
                last_seen_at=now, batch=batch
            )
        for key in rec.reopened_keys:
            ticket = VulnTicket.objects.get(dedup_key=key)
            evidence = dict(ticket.fix_evidence or {})
            evidence.update(
                {"reopened": True, "reopened_at": now.isoformat(),
                 "reopened_batch": batch.id}
            )
            ticket.state = TicketState.PENDING_FIX
            ticket.sla_due_at = None  # new SLA clock recomputed by Task5
            ticket.last_seen_at = now
            ticket.batch = batch
            ticket.fix_evidence = evidence
            ticket.save()
        for key in rec.fixed_unverified_keys:
            ticket = VulnTicket.objects.get(dedup_key=key)
            evidence = dict(ticket.fix_evidence or {})
            evidence.update(
                {"retest_status": RETEST_FIXED_UNVERIFIED,
                 "retest_at": now.isoformat(), "retest_batch": batch.id}
            )
            ticket.fix_evidence = evidence
            ticket.save(update_fields=["fix_evidence", "updated_at"])
        stats: dict[str, Any] = {
            "new": len(rec.new_keys),
            "still_open": len(rec.still_open_keys),
            "fixed_unverified": len(rec.fixed_unverified_keys),
            "reopened": len(rec.reopened_keys),
            "auto_assigned": auto_assigned,
            "low_ignored": low_ignored,
            "errors": list(parse_errors),
            "skipped": False,
            "field_map_version": FIELD_MAP_VERSION,
        }
        batch.stats_json = {**(batch.stats_json or {}), **stats}
        batch.save(update_fields=["stats_json"])
    return stats


def finding_to_ticket(
    finding: NormalizedFinding,
    dedup_key: str,
    now: datetime,
    batch: object,
) -> VulnTicket:
    """Build an unsaved VulnTicket for a brand-new finding."""
    return VulnTicket(
        dedup_key=dedup_key,
        ip=finding.ip,
        port=finding.port,
        protocol=finding.protocol,
        service=finding.service,
        plugin_id=finding.plugin_id,
        plugin_name=finding.plugin_name,
        cve=finding.cve,
        severity=finding.severity,
        cvss=finding.cvss,
        description=finding.description,
        solution=finding.solution,
        state=TicketState.PENDING_ASSIGN,
        first_seen_at=now,  # type: ignore[arg-type]
        last_seen_at=now,  # type: ignore[arg-type]
        batch=batch,  # type: ignore[arg-type]
    )


@shared_task(
    name="apps.imports.tasks.import_batch",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def import_batch(
    self: object, batch_id: int, rows: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Async parse/apply entry point.

    ``rows`` are JSON-serializable finding dicts (see
    :meth:`NormalizedFinding.to_dict`) so the task stays broker-safe for
    ``.delay()`` once Task9 wires Redis. Tests and the view call
    ``import_batch.run(batch_id, rows=...)`` synchronously; switching the
    view to ``.delay()`` later is a one-line change.
    """
    from apps.imports.models import ScanBatch

    del self  # unbound-task compatible; retries use the shared task object
    batch = ScanBatch.objects.get(id=batch_id)
    findings = [NormalizedFinding.from_dict(r) for r in (rows or [])]
    by_key = dedupe_findings(findings)
    rec = reconcile(by_key)
    return apply_reconciliation(batch, by_key, rec, [])


__all__ = [
    "RETEST_FIXED_UNVERIFIED", "Reconciliation", "apply_reconciliation",
    "dedup_key_for", "dedup_key_of", "dedupe_findings", "import_batch",
    "preview_import", "reconcile",
]
