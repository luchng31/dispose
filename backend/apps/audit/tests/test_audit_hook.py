from __future__ import annotations

import pytest

from apps.accounts.models import Role, User
from apps.audit.middleware import get_current_actor, set_current_actor
from apps.audit.models import AuditLog
from apps.tickets.models import Severity, TicketState, VulnTicket


@pytest.mark.django_db
def test_ticket_create_writes_audit_row_with_actor() -> None:
    actor: User = User.objects.create_user(
        username="writer1", password="pw-test-only-123", wecom_userid="writer1",
        role=Role.OPERATOR,
    )
    set_current_actor(actor)
    try:
        ticket: VulnTicket = VulnTicket.objects.create(
            dedup_key="f" * 32, ip="10.1.0.1", port=80, severity=Severity.HIGH
        )
    finally:
        set_current_actor(None)
    row = AuditLog.objects.filter(ticket=ticket, action="ticket.create").first()
    assert row is not None
    assert row.actor_id == actor.pk
    assert row.entity == "vuln_ticket"
    assert get_current_actor() is None


@pytest.mark.django_db
def test_ticket_update_writes_audit_row_with_diff() -> None:
    actor: User = User.objects.create_user(
        username="writer2", password="pw-test-only-123", wecom_userid="writer2",
        role=Role.OPERATOR,
    )
    ticket: VulnTicket = VulnTicket.objects.create(
        dedup_key="0" * 32, ip="10.1.0.2", port=443, severity=Severity.MEDIUM
    )
    set_current_actor(actor)
    try:
        ticket.state = TicketState.PENDING_FIX
        ticket.save()
    finally:
        set_current_actor(None)
    row = AuditLog.objects.filter(ticket=ticket, action="ticket.update").first()
    assert row is not None
    assert row.actor_id == actor.pk
    assert "state" in row.diff_json["changed"]


@pytest.mark.django_db
def test_ticket_noop_save_writes_no_audit_row() -> None:
    ticket: VulnTicket = VulnTicket.objects.create(
        dedup_key="1" * 32, ip="10.1.0.3", port=22, severity=Severity.LOW
    )
    before: int = AuditLog.objects.filter(ticket=ticket).count()
    ticket.save()
    assert AuditLog.objects.filter(ticket=ticket).count() == before
