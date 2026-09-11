"""RSAS report parsers (Task3): XML first, HTML/XLS via the same normalizer.

All entry points are pure (bytes in, rows + errors out) and NEVER raise on
bad input: failures are returned as per-row/per-file error dicts so one bad
row can never crash a batch.

FTP watcher contract (Task9 wires it, no watcher code here):
- Watcher drops RSAS exports under ``/data/rsas-reports`` (vsftpd chroot,
  reader-only account) and POSTs the file bytes to
  ``POST /api/imports/rsas?dry_run=...`` with an operator Bearer token.
- Manual uploads use the same endpoint from the ImportMgmt UI (Task8).
"""

from __future__ import annotations

import io
import zipfile
from typing import Any
from urllib.parse import urlparse

from lxml import etree
from lxml import html as lxml_html
from openpyxl import load_workbook

from .mapping import FieldMap, NormalizedFinding, RowError, load_field_map, normalize_row

# XML hardening: entities are NEVER resolved and no network access is allowed.
# RSAS uploads are untrusted input — resolving entities would enable
# billion-laughs/quadratic-blowup DoS and XXE (local file disclosure, SSRF).
# With resolve_entities=False the parser keeps entity references literal, so
# downstream rows can never see expanded payloads. The HTML path is unchanged
# (lxml_html does not resolve external entities by default).
_SECURE_XML_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)

_ITEM_TAGS = frozenset(
    {"vuln", "vulnerability", "finding", "result", "item", "row", "record"}
)
_HOST_TAGS = frozenset({"host", "asset", "ip"})
_PARSEABLE_ZIP_SUFFIXES = (".xml", ".html", ".htm", ".xls", ".xlsx")
_MAX_ZIP_MEMBER_BYTES: int = 50 * 1024 * 1024
_MAX_ZIP_MEMBERS: int = 200
_MAX_ZIP_TOTAL_BYTES: int = 200 * 1024 * 1024


def _local(tag: object) -> str:
    name = tag if isinstance(tag, str) else str(getattr(tag, "tag", tag))
    return str(name).rsplit("}", 1)[-1].strip().lower()


def _element_to_raw(el: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {str(k): v for k, v in el.attrib.items()}
    for child in el:
        if not isinstance(child.tag, str):
            continue
        text = (child.text or "").strip()
        if text and _local(child.tag) not in raw:
            raw[_local(child.tag)] = text
    return raw


def _target_ip(target: Any) -> str:
    for child in list(target):
        if _local(child.tag) == "ip":
            return "".join(child.itertext()).strip()
    return ""


def _site_endpoint(target: Any) -> tuple[str, int | None]:
    """Web-flavor aurora targets carry <site> URL (no <ip>): host + port.

    Port comes from an explicit :port in the URL, else the scheme default
    (https=443, http=80). Host may be a domain — the system keys tickets by
    this value (asset mapping can be added later, or ops dispatches manually).
    """
    site = ""
    for child in list(target):
        if _local(child.tag) == "site":
            site = "".join(child.itertext()).strip()
            break
    if not site:
        return "", None
    if "//" not in site:
        site = f"http://{site}"
    parsed = urlparse(site)
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return host, port


def _index_details(target: Any) -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for el in target.iter():
        if _local(el.tag) != "vuln":
            continue
        if _local(getattr(el.getparent(), "tag", "")) == "vuln_scanned":
            continue
        raw = _element_to_raw(el)
        vid = str(raw.get("vul_id", "")).strip()
        if vid:
            details[vid] = raw
    return details


def _is_scan_ref(el: Any) -> bool:
    return _local(el.tag) == "vuln" and _local(
        getattr(el.getparent(), "tag", "")) == "vuln_scanned"


def _with_severity(merged: dict[str, Any]) -> dict[str, Any]:
    if "severity" not in merged and merged.get("risk_points"):
        merged["severity"] = merged["risk_points"]
    return merged


def _aurora_target_endpoint(
    target: Any,
) -> tuple[str, int | None, dict[str, Any] | None]:
    """Resolve (ip, port, error) for one aurora target (host or web flavor)."""
    ip = _target_ip(target)
    if ip:
        return ip, None, None
    ip, port = _site_endpoint(target)
    if not ip:
        return "", None, {
            "row": "target", "field": "ip",
            "message": "target without ip/site; its vulns skipped",
        }
    return ip, port, None


def _aurora_collect_rows(target: Any, ip: str, port: int | None) -> list[dict[str, Any]]:
    """Join vuln_scanned refs with vuln_detail entries on vul_id for one target."""
    details = _index_details(target)
    target_rows: list[dict[str, Any]] = []
    matched: set[str] = set()
    for el in target.iter():
        if not _is_scan_ref(el):
            continue
        ref = _element_to_raw(el)
        vid = str(ref.get("vul_id", "")).strip()
        merged: dict[str, Any] = {"ip": ip}
        if vid and vid in details:
            matched.add(vid)
            merged.update(details[vid])
        merged.update({k: v for k, v in ref.items() if v not in ("", None)})
        target_rows.append(_with_severity(merged))
    for vid, detail in details.items():
        if vid in matched:
            continue
        merged = {"ip": ip}
        merged.update(detail)
        target_rows.append(_with_severity(merged))
    if port is not None:
        for row in target_rows:
            row.setdefault("port", port)
    return target_rows


def _aurora_target_rows(root: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Assemble rows from RSAS <aurora> report structure (host AND web flavor).

    Host flavor: ``report/targets/target`` carries ``<ip>`` plus
    ``<vuln_scanned/vuln>`` (per-port refs: port/protocol/service/vul_id)
    and ``<vuln_detail/vuln>`` (details: vul_id/plugin_id/name/cve_id/
    risk_points/solution/description), joined on ``vul_id``.

    Web flavor (webvul module, e.g. winning.com.cn exports): ``target`` has
    ``<site>`` URL instead of ``<ip>`` and empty ``<port/>`` refs — host and
    port derive from the site URL. Returns (rows, errors, handled).
    """
    targets = [el for el in root.iter() if _local(el.tag) == "target"]
    scanned = [el for el in root.iter() if _local(el.tag) == "vuln_scanned"]
    if not targets or not scanned:
        return [], [], False
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for target in targets:
        ip, port, error = _aurora_target_endpoint(target)
        if error is not None:
            errors.append(error)
            continue
        rows.extend(_aurora_collect_rows(target, ip, port))
    return rows, errors, True


def parse_xml_bytes(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse RSAS XML export. Returns (raw_rows, errors)."""
    try:
        root = etree.fromstring(data, parser=_SECURE_XML_PARSER)
    except etree.XMLSyntaxError as exc:
        return [], [{"row": "file", "field": "xml",
                     "message": f"malformed XML: {exc}"}]
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    aurora_rows, aurora_errors, handled = _aurora_target_rows(root)
    if handled:
        rows.extend(aurora_rows)
        errors.extend(aurora_errors)
        if not rows and not errors:
            errors.append({"row": "file", "field": "xml",
                           "message": "no vuln rows found in XML"})
        return rows, errors
    items = [el for el in root.iter() if _local(el.tag) in _ITEM_TAGS]
    if not items:
        hosts = [el for el in root.iter() if _local(el.tag) in _HOST_TAGS]
        items = hosts if hosts else [root]
    for idx, el in enumerate(items, start=1):
        try:
            host_ctx = el.getparent()
            base: dict[str, Any] = {}
            if host_ctx is not None and _local(host_ctx.tag) in _HOST_TAGS:
                base = {str(k): v for k, v in host_ctx.attrib.items()}
            merged = {**base, **_element_to_raw(el)}
            if not merged:
                continue
            rows.append(merged)
        except Exception as exc:  # per-row isolation: never crash the batch
            errors.append({"row": idx, "field": "xml",
                           "message": f"row unreadable: {exc}"})
    if not rows and not errors:
        errors.append({"row": "file", "field": "xml",
                       "message": "no vuln rows found in XML"})
    return rows, errors


def parse_html_bytes(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse RSAS HTML export (first <table> wins). Returns (raw_rows, errors)."""
    try:
        doc = lxml_html.fromstring(data)
    except Exception as exc:
        return [], [{"row": "file", "field": "html",
                     "message": f"malformed HTML: {exc}"}]
    tables = doc.xpath("//table")
    if not tables:
        return [], [{"row": "file", "field": "html",
                     "message": "no <table> found in HTML"}]
    table = tables[0]
    trs = table.xpath(".//tr")
    if len(trs) < 2:
        return [], [{"row": "file", "field": "html",
                     "message": "table has no data rows"}]
    headers = [(th.text_content() or "").strip() for th in trs[0].xpath(".//th|.//td")]
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for idx, tr in enumerate(trs[1:], start=2):
        try:
            cells = [(td.text_content() or "").strip() for td in tr.xpath(".//td")]
            if not any(cells):
                continue
            rows.append(dict(zip(headers, cells, strict=False)))
        except Exception as exc:
            errors.append({"row": idx, "field": "html",
                           "message": f"row unreadable: {exc}"})
    return rows, errors


def parse_xls_bytes(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse RSAS XLS/XLSX export (first sheet wins). Returns (raw_rows, errors)."""
    try:
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:
        return [], [{"row": "file", "field": "xls",
                     "message": f"unreadable workbook: {exc}"}]
    ws = wb.active
    if ws is None:
        return [], [{"row": "file", "field": "xls",
                     "message": "workbook has no active sheet"}]
    iterator = ws.iter_rows(values_only=True)
    try:
        header_row = next(iterator)
    except StopIteration:
        return [], [{"row": "file", "field": "xls",
                     "message": "sheet is empty"}]
    headers = ["" if h is None else str(h).strip() for h in header_row]
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for idx, values in enumerate(iterator, start=2):
        try:
            cells = ["" if v is None else str(v).strip() for v in values]
            if not any(cells):
                continue
            rows.append({h: c for h, c in zip(headers, cells, strict=False) if h})
        except Exception as exc:
            errors.append({"row": idx, "field": "xls",
                           "message": f"row unreadable: {exc}"})
    return rows, errors


def _parse_member(name: str, data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lower = name.lower()
    if lower.endswith(".xml"):
        return parse_xml_bytes(data)
    if lower.endswith((".html", ".htm")):
        return parse_html_bytes(data)
    if lower.endswith((".xls", ".xlsx")):
        return parse_xls_bytes(data)
    return [], [{"row": "file", "field": name,
                 "message": f"unsupported member type: {name}"}]


def parse_upload(
    filename: str, data: bytes
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Dispatch single file or ZIP walk. Returns (raw_rows, errors)."""
    lower = filename.lower()
    if lower.endswith(".zip"):
        rows: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            return [], [{"row": "file", "field": "zip",
                         "message": f"bad ZIP: {exc}"}]
        with archive:
            infos = [i for i in archive.infolist() if not i.is_dir()]
            parseable = [
                i for i in infos
                if i.filename.lower().endswith(_PARSEABLE_ZIP_SUFFIXES)
            ]
            total_expanded = sum(int(i.file_size) for i in parseable)
            if len(parseable) > _MAX_ZIP_MEMBERS or total_expanded > _MAX_ZIP_TOTAL_BYTES:
                return [], [{"row": "file", "field": "zip",
                             "message": "ZIP decompression limits exceeded "
                             f"({len(parseable)} members, {total_expanded} bytes expanded)"}]
            for info in parseable:
                member = info.filename
                if int(info.file_size) > _MAX_ZIP_MEMBER_BYTES:
                    errors.append({"row": "file", "field": member,
                                   "message": "member exceeds 50MB expanded; skipped"})
                    continue
                try:
                    payload = archive.read(member)
                except Exception as exc:
                    errors.append({"row": "file", "field": member,
                                   "message": f"cannot read member: {exc}"})
                    continue
                m_rows, m_errors = _parse_member(member, payload)
                rows.extend(m_rows)
                errors.extend(
                    {**e, "row": f"{member}:{e['row']}"} for e in m_errors
                )
        if not rows and not errors:
            errors.append({"row": "file", "field": "zip",
                           "message": "ZIP has no parseable XML/HTML/XLS members"})
        return rows, errors
    return _parse_member(filename, data)


def parse_and_normalize(
    filename: str,
    data: bytes,
    field_map: FieldMap | None = None,
) -> tuple[list[NormalizedFinding], list[dict[str, Any]]]:
    """Full pipeline: parse bytes -> normalize rows. Returns (findings, errors)."""
    fmap = field_map or load_field_map()
    raw_rows, errors = parse_upload(filename, data)
    findings: list[NormalizedFinding] = []
    for idx, raw in enumerate(raw_rows, start=1):
        try:
            findings.append(normalize_row(raw, row_no=idx, field_map=fmap))
        except RowError as exc:
            errors.append(exc.to_dict())
    return findings, errors


__all__ = [
    "parse_and_normalize", "parse_html_bytes", "parse_upload",
    "parse_xls_bytes", "parse_xml_bytes",
]
