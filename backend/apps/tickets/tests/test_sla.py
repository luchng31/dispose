"""Task5 RED: SLA compute + escalation levels + check_sla job (DB_ENGINE=sqlite)."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.tickets.escalation import next_level
from apps.tickets.models import Severity, SlaPolicy, TicketState, VulnTicket
from apps.tickets.sla import FALLBACK_SLA_DAYS, compute_due
from apps.tickets.tasks import check_sla


def _make_ticket(state: str, sla_due_at: object) -> VulnTicket:
    now = timezone.now()
    ticket = VulnTicket.objects.create(
        dedup_key=uuid.uuid4().hex,
        ip="10.9.0.2",
        port=80,
        protocol="tcp",
        plugin_id="RSAS-TEST-002",
        severity=Severity.HIGH,
        state=state,
        first_seen_at=now - timedelta(days=40),
        last_seen_at=now,
        sla_due_at=sla_due_at,  # type: ignore[arg-type]
    )
    return ticket


@pytest.mark.django_db
def test_compute_due_reads_seeded_policy() -> None:
    first_seen = timezone.now()
    assert compute_due(first_seen, Severity.CRITICAL) == first_seen + timedelta(days=7)
    assert compute_due(first_seen, Severity.HIGH) == first_seen + timedelta(days=30)
    assert compute_due(first_seen, Severity.MEDIUM) == first_seen + timedelta(days=90)
    assert compute_due(first_seen, Severity.LOW) == first_seen + timedelta(days=180)


@pytest.mark.django_db
def test_compute_due_falls_back_when_policy_table_empty() -> None:
    SlaPolicy.objects.all().delete()
    first_seen = timezone.now()
    for severity, days in FALLBACK_SLA_DAYS.items():
        assert compute_due(first_seen, severity) == first_seen + timedelta(days=days)


@pytest.mark.django_db
def test_next_level_matrix() -> None:
    now = timezone.now()
    assert next_level(_make_ticket(TicketState.PENDING_FIX, now + timedelta(days=30)), now) == 0
    assert next_level(_make_ticket(TicketState.PENDING_FIX, now + timedelta(days=1)), now) == 1
    assert next_level(_make_ticket(TicketState.PENDING_FIX, now - timedelta(hours=1)), now) == 2
    assert next_level(_make_ticket(TicketState.PENDING_FIX, now - timedelta(days=5)), now) == 3
    assert next_level(_make_ticket(TicketState.PENDING_FIX, now - timedelta(days=30)), now) == 4
    assert next_level(_make_ticket(TicketState.CLOSED, now - timedelta(days=30)), now) == 0


@pytest.mark.django_db
def test_check_sla_flags_overdue_and_calls_audit_hook() -> None:
    now = timezone.now()
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_FIX, now - timedelta(days=5))
    before: int = AuditLog.objects.count()
    result: dict[str, int] = check_sla.run() if hasattr(check_sla, "run") else check_sla()
    assert result["checked"] >= 1
    assert result["escalated"] >= 1
    ticket.refresh_from_db()
    assert ticket.fix_evidence.get("overdue") is True
    assert int(ticket.fix_evidence.get("escalation", 0)) >= 2
    assert AuditLog.objects.count() > before


@pytest.mark.django_db
def test_ignore_expiry_reopens() -> None:
    from apps.tickets.tasks import check_ignore_expiry

    now = timezone.now()
    past = now - timezone.timedelta(hours=1)
    future = now + timezone.timedelta(days=30)
    expired = _make_ticket(TicketState.IGNORED, now + timezone.timedelta(days=30))
    expired.fix_evidence = {"ignore_expires_at": past.isoformat()}
    expired.save(update_fields=["fix_evidence"])
    waiting = _make_ticket(TicketState.IGNORED, now + timezone.timedelta(days=30))
    waiting.fix_evidence = {"ignore_expires_at": future.isoformat()}
    waiting.save(update_fields=["fix_evidence"])
    result = check_ignore_expiry.run()
    assert result == {"checked": 2, "reopened": 1}
    expired.refresh_from_db()
    waiting.refresh_from_db()
    assert expired.state == TicketState.PENDING_FIX
    assert expired.fix_evidence.get("reopen_count") == 1
    assert "ignore_expires_at" not in expired.fix_evidence
    assert waiting.state == TicketState.IGNORED
