from __future__ import annotations

from unittest.mock import patch

import pytest

from apps.accounts.models import Role, User
from apps.tickets.models import TicketState, VulnTicket

PW = "pw-remind-123"


def _make_user(username: str, role: str, email: str = "") -> User:
    return User.objects.create_user(  # type: ignore[attr-defined]
        username=username,
        password=PW,
        wecom_userid=username,
        role=role,
        email=email,
    )


def _auth(username: str):
    from rest_framework.test import APIClient

    c = APIClient()
    r = c.post("/api/auth/local", {"username": username, "password": PW}, format="json")
    assert r.status_code == 200, r.content
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {r.data['jwt']}")  # type: ignore[union-attr]
    return c


def _make_ticket(ip: str, assignee: User | None = None, state: str = TicketState.PENDING_FIX) -> VulnTicket:
    import uuid

    from django.utils import timezone

    now = timezone.now()
    return VulnTicket.objects.create(
        dedup_key=uuid.uuid4().hex,
        ip=ip,
        port=443,
        protocol="tcp",
        plugin_id="RSAS-REMIND-001",
        plugin_name="提醒测试",
        severity="高",
        state=state,
        first_seen_at=now,
        last_seen_at=now,
        sla_due_at=now + timezone.timedelta(days=30),
        assignee=assignee,
    )


@pytest.mark.django_db
def test_remind_grouped_per_assignee_and_mock_send() -> None:
    _make_user("rem_op", Role.OPERATOR)
    a1 = _make_user("rem_a1", Role.OWNER, email="a1@example.com")
    a2 = _make_user("rem_a2", Role.OWNER, email="a2@example.com")
    t1 = _make_ticket("10.90.0.1", assignee=a1)
    t2 = _make_ticket("10.90.0.2", assignee=a1)
    t3 = _make_ticket("10.90.0.3", assignee=a2)
    t4 = _make_ticket("10.90.0.4", assignee=None)
    t5 = _make_ticket("10.90.0.5", assignee=a1, state=TicketState.CLOSED)

    client = _auth("rem_op")
    VulnTicket.objects.filter(pk__in=[t1.pk, t2.pk, t3.pk, t4.pk, t5.pk]).update(sla_due_at=None)
    with patch("apps.notify.mailer.send_ticket_mail", return_value=1) as mock:
        resp = client.post("/api/ops/remind", {"ids": [t1.pk, t2.pk, t3.pk, t4.pk, t5.pk]}, format="json")
    assert resp.status_code == 200, resp.content
    assert resp.data["requested"] == 5
    assert resp.data["sent_emails"] == 2
    assert resp.data["reminded_tickets"] == 3
    assert resp.data["skipped_unassigned"] == 1
    assert resp.data["skipped_cooldown"] == 0
    assert mock.call_count == 2
    # each emailed ticket gets last_reminded_at + audit + SLA clock started
    from apps.audit.models import AuditLog

    for t in (t1, t2, t3):
        t.refresh_from_db()
        assert "last_reminded_at" in t.fix_evidence
        assert t.sla_due_at is not None  # SLA 自首次提醒起算
    assert AuditLog.objects.filter(action="ticket.remind").count() == 3
    first_due = t1.sla_due_at
    # unassigned/closed not marked
    t4.refresh_from_db()
    assert "last_reminded_at" not in (t4.fix_evidence or {})
    assert t4.sla_due_at is None
    t5.refresh_from_db()
    assert "last_reminded_at" not in (t5.fix_evidence or {})
    # second remind within cooldown: no mail, SLA untouched
    with patch("apps.notify.mailer.send_ticket_mail", return_value=1):
        client.post("/api/ops/remind", {"ids": [t1.pk]}, format="json")
    t1.refresh_from_db()
    assert t1.sla_due_at == first_due


@pytest.mark.django_db
def test_remind_cooldown_skips_within_24h() -> None:
    _make_user("rem_op2", Role.OPERATOR)
    a1 = _make_user("rem_b1", Role.OWNER, email="b1@example.com")
    t1 = _make_ticket("10.91.0.1", assignee=a1)

    client = _auth("rem_op2")
    with patch("apps.notify.mailer.send_ticket_mail", return_value=1):
        r1 = client.post("/api/ops/remind", {"ids": [t1.pk]}, format="json")
    assert r1.data["sent_emails"] == 1
    with patch("apps.notify.mailer.send_ticket_mail", return_value=1) as mock:
        r2 = client.post("/api/ops/remind", {"ids": [t1.pk]}, format="json")
    assert r2.data["sent_emails"] == 0
    assert r2.data["skipped_cooldown"] == 1
    assert mock.call_count == 0


@pytest.mark.django_db
def test_remind_smtp_off_does_not_mark() -> None:
    _make_user("rem_op3", Role.OPERATOR)
    a1 = _make_user("rem_c1", Role.OWNER, email="c1@example.com")
    t1 = _make_ticket("10.92.0.1", assignee=a1)

    client = _auth("rem_op3")
    VulnTicket.objects.filter(pk=t1.pk).update(sla_due_at=None)
    with patch("apps.notify.mailer.send_ticket_mail", return_value=0) as mock:
        resp = client.post("/api/ops/remind", {"ids": [t1.pk]}, format="json")
    assert resp.data["sent_emails"] == 0
    assert resp.data["reminded_tickets"] == 0
    assert mock.call_count == 1
    t1.refresh_from_db()
    assert "last_reminded_at" not in (t1.fix_evidence or {})
    assert t1.sla_due_at is None  # 发送失败 = 未通知 = 不起算
    # retry should still be allowed
    with patch("apps.notify.mailer.send_ticket_mail", return_value=1) as mock2:
        resp2 = client.post("/api/ops/remind", {"ids": [t1.pk]}, format="json")
    assert resp2.data["sent_emails"] == 1
    assert mock2.call_count == 1


@pytest.mark.django_db
def test_remind_permissions_and_validation() -> None:
    _make_user("rem_owner", Role.OWNER)
    User.objects.create_user(username="rem_op4", password=PW, wecom_userid="rem_op4", role=Role.OPERATOR)  # type: ignore[attr-defined]
    t = _make_ticket("10.93.0.1")

    owner_cli = _auth("rem_owner")
    assert owner_cli.post("/api/ops/remind", {"ids": [t.pk]}, format="json").status_code == 403

    op_cli = _auth("rem_op4")
    assert op_cli.post("/api/ops/remind", {"ids": []}, format="json").status_code == 400
    assert op_cli.post("/api/ops/remind", {"ids": "bad"}, format="json").status_code == 400  # type: ignore[arg-type]
    assert op_cli.post("/api/ops/remind", {"ids": ["x"]}, format="json").status_code == 400
