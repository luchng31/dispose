"""SLA beat job + escalation persistence (Task5).

Celery beat wires check_sla() on a minute/hour cadence in Task9 deploy;
settings are already present (CELERY_* in config.settings).
Escalation level + overdue flag persist in fix_evidence JSON
{"escalation": n, "overdue": bool} — Task1 schema stays frozen.
WeCom notification is a log stub only; SMS gateway is Phase-2 CUT.
"""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


def _notify_wecom(ticket_id: int | str, level: int, sla_due_at: object) -> None:
    """Real WeCom group bot push on SLA escalation (was a log stub pre-P1)."""
    from apps.notify.wecom_bot import send_wecom_text

    send_wecom_text(
        f"【SLA升级 L{level}】工单#{ticket_id} 升级到 L{level}，"
        f"SLA到期 {sla_due_at}，请负责人尽快处理。"
    )


@shared_task(name="apps.tickets.tasks.check_sla")
def check_sla() -> dict[str, int]:
    """Flag overdue open tickets, persist escalation level, audit on rise."""
    from apps.tickets.escalation import next_level
    from apps.tickets.models import TicketState, VulnTicket
    from apps.tickets.transitions import _record_audit

    now = timezone.now()
    open_tickets = VulnTicket.objects.exclude(
        state__in=[TicketState.CLOSED, TicketState.IGNORED]
    ).select_related("assignee").only(
        "id", "fix_evidence", "sla_due_at", "state", "severity", "assignee"
    )
    checked: int = 0
    escalated: int = 0
    for ticket in open_tickets.iterator():
        level: int = next_level(ticket, now)
        evidence: dict[str, Any] = dict(ticket.fix_evidence or {})
        prev: int = int(evidence.get("escalation", 0))
        overdue: bool = ticket.sla_due_at is not None and now > ticket.sla_due_at
        if level == prev and bool(evidence.get("overdue", False)) == overdue:
            checked += 1
            continue
        evidence["escalation"] = level
        evidence["overdue"] = overdue
        ticket.fix_evidence = evidence
        ticket.save(update_fields=["fix_evidence", "updated_at"])
        if level > prev:
            _notify_wecom(ticket.pk, level, ticket.sla_due_at)
            from apps.notify.mailer import send_ticket_mail, ticket_line, user_email

            send_ticket_mail(
                [user_email(ticket.assignee)],
                f"SLA告警(L{level})：工单#{ticket.pk}",
                f"该工单SLA升级到 L{level}，请尽快处理。\n{ticket_line(ticket)}",
            )
            _record_audit(ticket, "system", str(ticket.state), str(ticket.state))
        checked += 1
        escalated += 1
    return {"checked": checked, "escalated": escalated}


def _parse_expiry(raw: object) -> Any:
    from datetime import datetime

    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return timezone.make_aware(parsed)
    return parsed


@shared_task(name="apps.tickets.tasks.check_ignore_expiry")
def check_ignore_expiry() -> dict[str, int]:
    """Reopen ignored tickets whose ignore_expires_at has passed."""
    from apps.tickets.models import TicketState, VulnTicket
    from apps.tickets.transitions import transition

    now = timezone.now()
    checked = 0
    reopened = 0
    for ticket in VulnTicket.objects.filter(state=TicketState.IGNORED).iterator():
        checked += 1
        evidence: dict[str, Any] = dict(ticket.fix_evidence or {})
        expiry = _parse_expiry(evidence.get("ignore_expires_at"))
        if expiry is None or expiry > now:
            continue
        evidence.pop("ignore_expires_at", None)
        ticket.fix_evidence = evidence
        ticket.save(update_fields=["fix_evidence", "updated_at"])
        transition(ticket, TicketState.PENDING_FIX, "system", {})
        from apps.notify.mailer import send_ticket_mail, ticket_line, user_email

        send_ticket_mail(
            [user_email(ticket.assignee)],
            f"忽略到期重开：工单#{ticket.pk}",
            f"该工单的忽略已到期，自动重开为待修复。\n{ticket_line(ticket)}",
        )
        reopened += 1
    return {"checked": checked, "reopened": reopened}
