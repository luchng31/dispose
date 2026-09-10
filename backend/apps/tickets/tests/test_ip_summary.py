"""ip-summary: server-side per-IP rollup over the full filtered set.

Contract: same visibility + filter semantics as GET /api/tickets/my
(owner-isolated via get_visible_tickets; bad state/severity -> 400).
Totals must span beyond page 1 (client-side group-by undercounts).
"""

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
        "plugin_id": "RSAS-IPSUM-001",
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
def summary_db(db: Any) -> dict[str, Any]:
    owner_a: User = _make_user("sum_owner_a", Role.OWNER)
    owner_b: User = _make_user("sum_owner_b", Role.OWNER)
    _make_user("sum_operator", Role.OPERATOR)
    Asset.objects.create(ip="10.30.0.1")
    Asset.objects.create(ip="10.30.0.2")
    now = timezone.now()
    AssetOwnerMap.objects.create(ip_id="10.30.0.1", user=owner_a, valid_from=now)
    AssetOwnerMap.objects.create(ip_id="10.30.0.2", user=owner_b, valid_from=now)
    _make_ticket("10.30.0.1", severity=Severity.CRITICAL)
    _make_ticket(
        "10.30.0.1",
        severity=Severity.LOW,
        sla_due_at=now - timezone.timedelta(days=2),
    )
    _make_ticket(
        "10.30.0.1",
        severity=Severity.HIGH,
        state=TicketState.CLOSED,
        sla_due_at=now - timezone.timedelta(days=2),
    )
    _make_ticket("10.30.0.2", severity=Severity.HIGH)
    return {"owner_a": owner_a, "owner_b": owner_b}


def _rows(resp: Any) -> dict[str, Any]:
    assert resp.status_code == 200, resp.content
    return {row["ip"]: row for row in resp.data["results"]}


@pytest.mark.django_db
def test_owner_sees_only_own_ips_with_breakdown(summary_db: dict[str, Any]) -> None:
    rows = _rows(_auth("sum_owner_a").get("/api/tickets/ip-summary"))
    assert set(rows) == {"10.30.0.1"}
    mine = rows["10.30.0.1"]
    assert mine["total"] == 3
    assert mine["overdue"] == 1
    assert mine["severities"]["严重"] == 1
    assert mine["severities"]["高"] == 1
    assert mine["severities"]["低"] == 1
    assert mine["severities"]["中"] == 0


@pytest.mark.django_db
def test_operator_sees_all_ips(summary_db: dict[str, Any]) -> None:
    rows = _rows(_auth("sum_operator").get("/api/tickets/ip-summary"))
    assert set(rows) == {"10.30.0.1", "10.30.0.2"}


@pytest.mark.django_db
def test_filters_narrow_the_rollup(summary_db: dict[str, Any]) -> None:
    client = _auth("sum_operator")
    rows = _rows(client.get("/api/tickets/ip-summary", {"severity": "严重"}))
    assert rows["10.30.0.1"]["total"] == 1
    assert "10.30.0.2" not in rows
    rows = _rows(client.get("/api/tickets/ip-summary", {"state": "已闭合"}))
    assert rows["10.30.0.1"]["total"] == 1
    assert rows["10.30.0.1"]["overdue"] == 0
    rows = _rows(client.get("/api/tickets/ip-summary", {"q": "10.30.0.2"}))
    assert set(rows) == {"10.30.0.2"}


@pytest.mark.django_db
def test_bad_severity_400(summary_db: dict[str, Any]) -> None:
    resp = _auth("sum_owner_a").get("/api/tickets/ip-summary", {"severity": "critical"})
    assert resp.status_code == 400
    assert "严重" in resp.data["allowed"]


@pytest.mark.django_db
def test_totals_span_beyond_page_one(summary_db: dict[str, Any]) -> None:
    for _ in range(25):
        _make_ticket("10.30.0.1")
    rows = _rows(_auth("sum_owner_a").get("/api/tickets/ip-summary"))
    assert rows["10.30.0.1"]["total"] == 28


@pytest.mark.django_db
def test_unauthenticated_401(summary_db: dict[str, Any]) -> None:
    resp = APIClient().get("/api/tickets/ip-summary")
    assert resp.status_code in (401, 403)
