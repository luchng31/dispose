"""Notify tests: SMTP hooks via locmem backend, never touch the network."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.core import mail
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.assets.models import Asset, AssetOwnerMap
from apps.tickets.models import Severity, TicketState, VulnTicket

PW: str = "pw-notify-test-123"


def _make_user(username: str, role: str, email: str = "") -> User:
    user: User = User.objects.create_user(
        username=username, password=PW, wecom_userid=username, role=role, email=email
    )
    return user


def _auth(username: str) -> APIClient:
    client = APIClient()
    login = client.post(
        "/api/auth/local", {"username": username, "password": PW}, format="json"
    )
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


@pytest.fixture
def notify_db(db: Any) -> dict[str, Any]:
    owner: User = _make_user("nt_owner", Role.OWNER, email="owner@example.com")
    operator: User = _make_user("nt_op", Role.OPERATOR, email="op@example.com")
    Asset.objects.create(ip="10.30.0.1")
    now = timezone.now()
    AssetOwnerMap.objects.create(ip_id="10.30.0.1", user=owner, valid_from=now)
    ticket = VulnTicket.objects.create(
        dedup_key=uuid.uuid4().hex, ip="10.30.0.1", port=443, protocol="tcp",
        plugin_id="RSAS-NOTIFY-001", plugin_name="通知测试漏洞",
        severity=Severity.HIGH, state=TicketState.PENDING_ASSIGN,
        first_seen_at=now, last_seen_at=now,
        sla_due_at=now + timezone.timedelta(days=30),
    )
    return {"owner": owner, "operator": operator, "ticket": ticket}


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    NOTIFY_ENABLED=True, EMAIL_HOST="smtp.example.com",
    DEFAULT_FROM_EMAIL="sec@example.com",
)
@pytest.mark.django_db
def test_assign_sends_mail(notify_db: dict[str, Any]) -> None:
    ticket: VulnTicket = notify_db["ticket"]
    op = _auth("nt_op")
    resp = op.post(
        f"/api/ops/{ticket.pk}/assign", {"assignee": "nt_owner"}, format="json"
    )
    assert resp.status_code == 200, resp.content
    assert len(mail.outbox) == 0  # auto-mail removed: manual remind via POST /api/ops/remind


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    NOTIFY_ENABLED=False,
)
@pytest.mark.django_db
def test_disabled_sends_nothing(notify_db: dict[str, Any]) -> None:
    ticket: VulnTicket = notify_db["ticket"]
    op = _auth("nt_op")
    resp = op.post(
        f"/api/ops/{ticket.pk}/assign", {"assignee": "nt_owner"}, format="json"
    )
    assert resp.status_code == 200, resp.content
    assert len(mail.outbox) == 0


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    NOTIFY_ENABLED=True, EMAIL_HOST="smtp.example.com",
    DEFAULT_FROM_EMAIL="sec@example.com",
)
@pytest.mark.django_db
def test_submit_notifies_operators(notify_db: dict[str, Any]) -> None:
    ticket: VulnTicket = notify_db["ticket"]
    ticket.state = TicketState.PENDING_FIX
    ticket.assignee = notify_db["owner"]
    ticket.save()
    owner = _auth("nt_owner")
    resp = owner.post(
        f"/api/tickets/{ticket.pk}/submit",
        {"evidence": {"note": "修了"}},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert len(mail.outbox) == 0  # auto-mail removed: manual remind via POST /api/ops/remind


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    NOTIFY_ENABLED=True, EMAIL_HOST="smtp.example.com",
    DEFAULT_FROM_EMAIL="sec@example.com",
)
@pytest.mark.django_db
def test_notify_status_and_test_endpoint(notify_db: dict[str, Any]) -> None:
    del notify_db
    op = _auth("nt_op")
    status = op.get("/api/ops/notify/status")
    assert status.status_code == 200
    assert status.data["configured"] is True
    assert "PASSWORD" not in str(status.data).upper()
    test = op.post("/api/ops/notify/test", {"to": "me@example.com"}, format="json")
    assert test.status_code == 200
    assert test.data["sent"] == 1
    assert len(mail.outbox) == 1
