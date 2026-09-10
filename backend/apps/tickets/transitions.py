"""Ticket state machine (Task5, whitelist-only).

State diagram::

    待分配 --assign--> 待修复 --submit--> 待复测 --close(operator)--> 已闭合
                         |                   |
                         | delay             | reject
                         v                   v
                       已延期              待修复
    * --ignore(operator+reason)--> 已忽略
    已闭合 --reopen--> 待修复 (reopen_count+1, new SLA)
    已延期 --resume--> 待修复

Any edge not listed above raises ValidationError (Task6 maps it to HTTP 422).
Only the operator role may enter 已闭合 (fraud control, enforced here even
before Task2 RBAC lands; Task6 adds the HTTP 403 layer later).
Task6 decision: KEEP 已延期--resume-->待修复, exposed as POST
/api/tickets/:id/resume (operationally necessary: delay ends, work resumes).

reopen_count and escalation levels live in fix_evidence JSON because the
Task1 schema is frozen (no new model field, no migration).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.tickets.models import TicketState, VulnTicket

logger = logging.getLogger(__name__)

OPERATOR_ROLE: str = "operator"
LEADER_ROLE: str = "leader"
_DELAY_CO_APPROVE_THRESHOLD_DAYS: int = 30

# Guard signature: raise ValidationError/PermissionDenied with Chinese message.
GuardFn = Callable[[str, dict[str, Any]], None]


def _guard_assign(actor_role: str, payload: dict[str, Any]) -> None:
    _ = (actor_role, payload)


def _guard_submit(actor_role: str, payload: dict[str, Any]) -> None:
    _ = (actor_role, payload)


def _guard_close(actor_role: str, payload: dict[str, Any]) -> None:
    _ = payload
    if actor_role != OPERATOR_ROLE:
        raise PermissionDenied("仅运营可关闭工单")


def _guard_reject(actor_role: str, payload: dict[str, Any]) -> None:
    _ = (actor_role, payload)


def _guard_resume(actor_role: str, payload: dict[str, Any]) -> None:
    _ = (actor_role, payload)


def _delay_days(payload: dict[str, Any]) -> int:
    if "delay_days" in payload:
        return int(payload["delay_days"])
    if "delay_until" in payload:
        until = payload["delay_until"]
        if isinstance(until, datetime):
            delta = (until - timezone.now()).days
            return max(delta, 0)
        raise ValidationError("delay_until 需为日期时间")
    raise ValidationError("延期需提供 delay_days 或 delay_until")


def _guard_delay(actor_role: str, payload: dict[str, Any]) -> None:
    if actor_role not in {OPERATOR_ROLE, LEADER_ROLE}:
        raise PermissionDenied("延期需负责人及以上审批")
    if actor_role == OPERATOR_ROLE:
        return
    if _delay_days(payload) > _DELAY_CO_APPROVE_THRESHOLD_DAYS:
        if payload.get("co_approved_by") != OPERATOR_ROLE:
            raise PermissionDenied("超过30天的延期需运营共同审批")


def _guard_ignore(actor_role: str, payload: dict[str, Any]) -> None:
    if actor_role != OPERATOR_ROLE:
        raise PermissionDenied("仅运营可忽略工单")
    reason = payload.get("reason", payload.get("ignore_reason", ""))
    if not str(reason).strip():
        raise ValidationError("忽略需填写原因")


def _guard_reopen(actor_role: str, payload: dict[str, Any]) -> None:
    _ = (actor_role, payload)


# Exhaustive whitelist: from_state -> {to_state: guard}. Anything absent is 422.
_ALLOWED: dict[str, dict[str, GuardFn]] = {
    TicketState.PENDING_ASSIGN: {
        TicketState.PENDING_FIX: _guard_assign,
        TicketState.IGNORED: _guard_ignore,
    },
    TicketState.PENDING_FIX: {
        TicketState.PENDING_RETEST: _guard_submit,
        TicketState.DELAYED: _guard_delay,
        TicketState.IGNORED: _guard_ignore,
    },
    TicketState.PENDING_RETEST: {
        TicketState.CLOSED: _guard_close,
        TicketState.PENDING_FIX: _guard_reject,
        TicketState.IGNORED: _guard_ignore,
    },
    TicketState.DELAYED: {
        TicketState.PENDING_FIX: _guard_resume,
        TicketState.IGNORED: _guard_ignore,
    },
    TicketState.CLOSED: {
        TicketState.PENDING_FIX: _guard_reopen,
        TicketState.IGNORED: _guard_ignore,
    },
    TicketState.IGNORED: {
        TicketState.PENDING_FIX: _guard_reopen,
    },
}


def _record_audit(ticket: VulnTicket, actor_role: str, from_state: str, to_state: str) -> None:
    """Audit every transition via Task2 hook if importable, else minimal row.

    TODO(Task2): switch to the canonical audit hook once it lands; this
    fallback must never crash transition() when the module path differs.
    """
    diff: dict[str, Any] = {"from": from_state, "to": to_state, "actor_role": actor_role}
    try:
        from apps.audit.hooks import record_ticket_transition  # type: ignore[import-not-found]

        record_ticket_transition(ticket=ticket, actor_role=actor_role, diff=diff)
        return
    except ImportError:
        pass
    try:
        from apps.audit.models import AuditLog

        AuditLog.objects.create(
            action="ticket.transition",
            ticket=ticket,
            entity="VulnTicket",
            entity_id=str(ticket.pk),
            diff_json=diff,
        )
    except Exception as exc:  # audit must never break the ticket flow
        logger.warning("audit fallback write failed: %s", exc)


@transaction.atomic
def transition(
    ticket: VulnTicket,
    to_state: str,
    actor_role: str,
    payload: dict[str, Any] | None = None,
) -> VulnTicket:
    """Move ticket along a whitelisted edge; raise ValidationError otherwise."""
    data: dict[str, Any] = dict(payload) if payload else {}
    from_state: str = str(ticket.state)
    guard: GuardFn | None = _ALLOWED.get(from_state, {}).get(to_state)
    if guard is None:
        raise ValidationError(f"非法状态流转：{from_state}→{to_state}")
    guard(actor_role, data)

    evidence: dict[str, Any] = dict(ticket.fix_evidence or {})
    if to_state == TicketState.PENDING_RETEST and isinstance(data.get("fix_evidence"), dict):
        evidence.update(data["fix_evidence"])
    if to_state == TicketState.PENDING_FIX and isinstance(data.get("reject_reason"), str):
        evidence["reject_reason"] = data["reject_reason"]

    if to_state == TicketState.DELAYED:
        days: int = _delay_days(data)
        ticket.delay_until = timezone.now() + timezone.timedelta(days=days)
    if to_state == TicketState.IGNORED:
        ticket.ignore_reason = str(data.get("reason", data.get("ignore_reason", "")))

    if from_state in (TicketState.CLOSED, TicketState.IGNORED) and to_state == TicketState.PENDING_FIX:
        from apps.tickets.sla import compute_due

        evidence["reopen_count"] = int(evidence.get("reopen_count", 0)) + 1
        evidence["reopened_from"] = ticket.pk
        evidence["reopened_at"] = timezone.now().isoformat()
        ticket.sla_due_at = compute_due(timezone.now(), str(ticket.severity))
        ticket.delay_until = None
        ticket.ignore_reason = ""

    ticket.state = to_state
    ticket.fix_evidence = evidence
    ticket.save()
    _record_audit(ticket, actor_role, from_state, to_state)
    return ticket
