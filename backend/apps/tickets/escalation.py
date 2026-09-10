"""Escalation level computation (Task5).

Chain: 0 none -> 1 T-3d reminder -> 2 overdue -> 3 leader -> 4 broadcast.
Pure function of (ticket state, sla_due_at, now); no DB writes here.
The Celery beat job in tasks.py persists the level into
fix_evidence JSON {"escalation": n, "overdue": bool} to keep the
Task1 schema frozen (no new model field, no migration).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from django.utils import timezone

from apps.tickets.sla import warn_days_for

if TYPE_CHECKING:
    from apps.tickets.models import VulnTicket

# Terminal states never escalate.
_QUIET_STATES: frozenset[str] = frozenset({"已闭合", "已忽略"})

# Overdue thresholds (days) for leader / broadcast escalation.
_LEADER_AFTER_DAYS: float = 3.0
_BROADCAST_AFTER_DAYS: float = 7.0


def next_level(ticket: VulnTicket, now: datetime | None = None) -> int:
    """Return escalation level 0-4 for a ticket at `now` (pure, no writes)."""
    at: datetime = now if now is not None else timezone.now()
    if ticket.state in _QUIET_STATES or ticket.sla_due_at is None:
        return 0
    delta_seconds: float = (at - ticket.sla_due_at).total_seconds()
    if delta_seconds < 0:
        warn_window: float = float(warn_days_for(str(ticket.severity))) * 86400.0
        return 1 if -delta_seconds <= warn_window else 0
    overdue_days: float = delta_seconds / 86400.0
    if overdue_days > _BROADCAST_AFTER_DAYS:
        return 4
    if overdue_days > _LEADER_AFTER_DAYS:
        return 3
    return 2
