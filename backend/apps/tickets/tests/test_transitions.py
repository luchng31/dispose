"""Task5 RED: transition whitelist matrix (Task1 models frozen, DB_ENGINE=sqlite)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.tickets.models import Severity, TicketState, VulnTicket
from apps.tickets.transitions import transition


def _make_ticket(state: str = TicketState.PENDING_ASSIGN) -> VulnTicket:
    now = timezone.now()
    return VulnTicket.objects.create(
        dedup_key=uuid.uuid4().hex,
        ip="10.9.0.1",
        port=443,
        protocol="tcp",
        plugin_id="RSAS-TEST-001",
        severity=Severity.HIGH,
        state=state,
        first_seen_at=now,
        last_seen_at=now,
        sla_due_at=now + timezone.timedelta(days=30),
    )


@pytest.mark.django_db
def test_illegal_jump_pending_assign_to_closed_rejected_without_db_change() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_ASSIGN)
    before_evidence: dict[str, Any] = dict(ticket.fix_evidence)
    with pytest.raises(ValidationError):
        transition(ticket, TicketState.CLOSED, actor_role="operator", payload={})
    ticket.refresh_from_db()
    assert ticket.state == TicketState.PENDING_ASSIGN
    assert ticket.fix_evidence == before_evidence


@pytest.mark.django_db
def test_owner_submit_pending_fix_to_pending_retest() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_FIX)
    out: VulnTicket = transition(
        ticket, TicketState.PENDING_RETEST, actor_role="owner",
        payload={"fix_evidence": {"note": "已修复并自验证"}},
    )
    assert out.state == TicketState.PENDING_RETEST


@pytest.mark.django_db
def test_non_operator_close_rejected_with_permission_denied() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_RETEST)
    with pytest.raises(PermissionDenied):
        transition(ticket, TicketState.CLOSED, actor_role="owner", payload={})
    ticket.refresh_from_db()
    assert ticket.state == TicketState.PENDING_RETEST


@pytest.mark.django_db
def test_operator_close_ok_and_audit_hook_called() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_RETEST)
    before: int = AuditLog.objects.count()
    out: VulnTicket = transition(ticket, TicketState.CLOSED, actor_role="operator", payload={})
    assert out.state == TicketState.CLOSED
    # Task2's post_save signal also audits writes, so assert growth + our row.
    assert AuditLog.objects.count() >= before + 1
    assert AuditLog.objects.filter(
        action="ticket.transition", ticket=ticket,
        diff_json__actor_role="operator",
    ).exists()


@pytest.mark.django_db
def test_delay_leader_short_ok_long_needs_operator_coapprove() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_FIX)
    out: VulnTicket = transition(
        ticket, TicketState.DELAYED, actor_role="leader", payload={"delay_days": 10}
    )
    assert out.state == TicketState.DELAYED
    assert out.delay_until is not None

    ticket2: VulnTicket = _make_ticket(TicketState.PENDING_FIX)
    with pytest.raises(PermissionDenied):
        transition(ticket2, TicketState.DELAYED, actor_role="leader", payload={"delay_days": 60})
    out2: VulnTicket = transition(
        ticket2, TicketState.DELAYED, actor_role="leader",
        payload={"delay_days": 60, "co_approved_by": "operator"},
    )
    assert out2.state == TicketState.DELAYED

    ticket3: VulnTicket = _make_ticket(TicketState.PENDING_FIX)
    with pytest.raises(PermissionDenied):
        transition(ticket3, TicketState.DELAYED, actor_role="owner", payload={"delay_days": 5})


@pytest.mark.django_db
def test_ignore_requires_operator_and_reason() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_FIX)
    with pytest.raises(ValidationError):
        transition(ticket, TicketState.IGNORED, actor_role="operator", payload={})
    with pytest.raises(PermissionDenied):
        transition(ticket, TicketState.IGNORED, actor_role="owner", payload={"reason": "测试"})
    out: VulnTicket = transition(
        ticket, TicketState.IGNORED, actor_role="operator", payload={"reason": "误报确认"}
    )
    assert out.state == TicketState.IGNORED
    assert out.ignore_reason == "误报确认"


@pytest.mark.django_db
def test_reopen_closed_resets_sla_and_bumps_reopen_count() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.CLOSED)
    old_due = ticket.sla_due_at
    out: VulnTicket = transition(ticket, TicketState.PENDING_FIX, actor_role="owner", payload={})
    assert out.state == TicketState.PENDING_FIX
    assert out.fix_evidence.get("reopen_count") == 1
    assert out.fix_evidence.get("reopened_from") == ticket.pk
    assert out.sla_due_at is not None
    assert out.sla_due_at != old_due


@pytest.mark.django_db
def test_reject_retest_back_to_fix() -> None:
    ticket: VulnTicket = _make_ticket(TicketState.PENDING_RETEST)
    out: VulnTicket = transition(
        ticket, TicketState.PENDING_FIX, actor_role="operator",
        payload={"reject_reason": "复测仍存在"},
    )
    assert out.state == TicketState.PENDING_FIX
