"""Task6 query-param filters: validated state/severity/q + pool flags.

Bad ``state``/``severity`` values return HTTP 400 with the allowed list
instead of silently ignoring the filter (frontend lane depends on this).
"""

from __future__ import annotations

from django.db.models import Q, QuerySet

from apps.assets.models import AssetOwnerMap
from apps.tickets.models import Severity, TicketState, VulnTicket

SEVERITY_VALUES: list[str] = list(Severity.values)
STATE_VALUES: list[str] = list(TicketState.values)

_TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})


class FilterValidationError(Exception):
    """Raised on a bad query param; the view maps it to HTTP 400."""

    def __init__(self, detail: str, allowed: list[str]) -> None:
        super().__init__(detail)
        self.detail: str = detail
        self.allowed: list[str] = allowed


def is_truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in _TRUTHY


def _checked(value: str | None, allowed: list[str], name: str) -> str | None:
    text: str = str(value or "").strip()
    if not text:
        return None
    if text not in allowed:
        raise FilterValidationError(f"非法{name}：{text}", allowed)
    return text


def _checked_list(value: str | None, allowed: list[str], name: str) -> list[str] | None:
    """Comma-separated multi-select (?severity=高,中); each item validated."""
    text: str = str(value or "").strip()
    if not text:
        return None
    items = [p.strip() for p in text.split(",") if p.strip()]
    bad = [p for p in items if p not in allowed]
    if bad:
        raise FilterValidationError(f"非法{name}：{','.join(bad)}", allowed)
    seen = list(dict.fromkeys(items))
    return seen or None


def apply_my_filters(qs: QuerySet[VulnTicket], params: dict[str, str]) -> QuerySet[VulnTicket]:
    """Apply ?state=&severity=&q= for GET /api/tickets/my (severity 可逗号多选)."""
    state: str | None = _checked(params.get("state"), STATE_VALUES, "state")
    if state is not None:
        qs = qs.filter(state=state)
    severities: list[str] | None = _checked_list(
        params.get("severity"), SEVERITY_VALUES, "severity"
    )
    if severities is not None:
        qs = qs.filter(severity__in=severities)
    query: str = str(params.get("q", "") or "").strip()
    if query:
        qs = qs.filter(
            Q(ip__icontains=query)
            | Q(plugin_name__icontains=query)
            | Q(plugin_id__icontains=query)
            | Q(cve__icontains=query)
        )
    return qs


def apply_pool_filters(qs: QuerySet[VulnTicket], params: dict[str, str]) -> QuerySet[VulnTicket]:
    """Apply ?orphan=&unassigned=&state=&severity=&q= for GET /api/ops/pool.

    unassigned: assignee 为 NULL 的待认领工单；orphan: 其中的 IP 在当前
    AssetOwnerMap 中无有效负责人的子集（同样要求 assignee NULL）。
    手工派单设置 assignee 后，工单同时退出两列；IP 归属缺口改去
    资产管理 -> 无主资产（asset 侧）补映射。
    severity: 四档之一，可逗号多选（非法 400）；q: IP/插件名/插件ID/CVE/标题/
    负责人用户名/企微账号 模糊匹配。
    dept: 负责人部门精确匹配（完整原串，来自 /api/ops/departments 树值）；
    dept_prefix: 负责人部门前缀匹配（一级部门筛选用）。
    """
    state: str | None = _checked(params.get("state"), STATE_VALUES, "state")
    if state is not None:
        qs = qs.filter(state=state)
    severities: list[str] | None = _checked_list(
        params.get("severity"), SEVERITY_VALUES, "severity"
    )
    if severities is not None:
        qs = qs.filter(severity__in=severities)
    query: str = str(params.get("q", "") or "").strip()
    if query:
        qs = qs.filter(
            Q(ip__icontains=query)
            | Q(plugin_name__icontains=query)
            | Q(plugin_id__icontains=query)
            | Q(cve__icontains=query)
            | Q(assignee__username__icontains=query)
            | Q(assignee__wecom_userid__icontains=query)
        )
    if is_truthy(params.get("unassigned")):
        qs = qs.filter(assignee__isnull=True)
    if is_truthy(params.get("orphan")):
        mapped = AssetOwnerMap.objects.filter(valid_to__isnull=True).values("ip_id")
        qs = qs.filter(assignee__isnull=True).exclude(ip__in=mapped)
    dept: str = str(params.get("dept", "") or "").strip()
    if dept:
        qs = qs.filter(assignee__dept=dept)
    dept_prefix: str = str(params.get("dept_prefix", "") or "").strip()
    if dept_prefix:
        qs = qs.filter(assignee__dept__startswith=dept_prefix)
    return qs
