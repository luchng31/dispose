"""My export: owner-isolated CSV over the same filters as /my."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.assets.models import Asset, AssetOwnerMap
from apps.tickets.models import Severity, TicketState, VulnTicket

PW: str = "pw-test-only-123"


def _make_user(username: str, role: str) -> User:
    return User.objects.create_user(  # type: ignore[arg-type]
        username=username, password=PW, wecom_userid=username, role=role
    )


def _auth(username: str) -> APIClient:
    client = APIClient()
    login = client.post(
        "/api/auth/local",
        {"username": username, "password": PW},
        format="json",
    )
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


def _make_ticket(ip: str, **kwargs: Any) -> VulnTicket:
    now = timezone.now()
    params: dict[str, Any] = {
        "dedup_key": uuid.uuid4().hex,
        "ip": ip,
        "port": 443,
        "protocol": "tcp",
        "plugin_id": "RSAS-EXP-001",
        "plugin_name": "演示漏洞",
        "severity": Severity.HIGH,
        "state": TicketState.PENDING_FIX,
        "first_seen_at": now,
        "last_seen_at": now,
        "sla_due_at": now + timezone.timedelta(days=30),
    }
    params.update(kwargs)
    return VulnTicket.objects.create(**params)


@pytest.fixture
def export_db(db: Any) -> None:
    owner_a = _make_user("ex_owner_a", Role.OWNER)
    owner_b = _make_user("ex_owner_b", Role.OWNER)
    _make_user("ex_operator", Role.OPERATOR)
    Asset.objects.create(ip="10.40.0.1")
    Asset.objects.create(ip="10.40.0.2")
    now = timezone.now()
    AssetOwnerMap.objects.create(ip_id="10.40.0.1", user=owner_a, valid_from=now)
    AssetOwnerMap.objects.create(ip_id="10.40.0.2", user=owner_b, valid_from=now)
    _make_ticket("10.40.0.1", severity=Severity.CRITICAL)
    _make_ticket("10.40.0.1", severity=Severity.LOW)
    _make_ticket("10.40.0.2", severity=Severity.HIGH)


def _csv_text(resp: Any) -> str:
    assert resp.status_code == 200, resp.content
    assert resp["Content-Type"].startswith("text/csv")
    raw: bytes = resp.content
    return raw.decode("utf-8-sig")


@pytest.mark.django_db
def test_owner_exports_only_mine(export_db: None) -> None:
    text = _csv_text(_auth("ex_owner_a").get("/api/tickets/my/export"))
    lines = text.strip().splitlines()
    assert lines[0].startswith("ID,IP")
    assert len(lines) == 3
    assert "10.40.0.2" not in text


@pytest.mark.django_db
def test_export_honors_filters(export_db: None) -> None:
    text = _csv_text(_auth("ex_owner_a").get("/api/tickets/my/export", {"severity": "严重"}))
    assert len(text.strip().splitlines()) == 2


@pytest.mark.django_db
def test_export_bad_filter_400(export_db: None) -> None:
    resp = _auth("ex_owner_a").get("/api/tickets/my/export", {"severity": "critical"})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_export_unauthenticated_denied(export_db: None) -> None:
    assert APIClient().get("/api/tickets/my/export").status_code in (401, 403)


@pytest.mark.django_db
def test_pool_export_escapes_formula_cells(export_db: None) -> None:
    _make_ticket("10.40.0.9", plugin_name="=1+1", severity=Severity.HIGH)
    text = _csv_text(_auth("ex_operator").get("/api/ops/pool/export"))
    assert "'=1+1" in text
