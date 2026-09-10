"""SLA due-date computation (Task5).

Pure helpers reading the SlaPolicy table. If the table is empty (or the
lookup fails), fall back to the seeded constants 7/30/90/180 so the ticket
flow never breaks on missing policy rows.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Fallback when SlaPolicy has no row for a severity (seed: 7/30/90/180).
FALLBACK_SLA_DAYS: dict[str, int] = {"严重": 7, "高": 30, "中": 90, "低": 180}


def sla_days_for(severity: str) -> int:
    """Return SLA days for a severity, preferring the SlaPolicy table."""
    try:
        from apps.tickets.models import SlaPolicy

        policy = SlaPolicy.objects.filter(severity=severity).first()
        if policy is not None:
            return int(policy.days)
    except Exception as exc:  # table missing mid-migration etc.: fall back, never crash
        logger.warning("sla_policy lookup failed, using fallback: %s", exc)
    return int(FALLBACK_SLA_DAYS.get(severity, 30))


def compute_due(first_seen: datetime, severity: str) -> datetime:
    """Return first_seen + SLA days for the given severity (pure)."""
    return first_seen + timedelta(days=sla_days_for(severity))


def warn_days_for(severity: str) -> int:
    """Return T-minus reminder window (days) for a severity; default 3."""
    try:
        from apps.tickets.models import SlaPolicy

        policy = SlaPolicy.objects.filter(severity=severity).first()
        if policy is not None:
            return int(policy.warn_days_before)
    except Exception as exc:
        logger.warning("sla_policy warn lookup failed, using default 3: %s", exc)
    return 3
