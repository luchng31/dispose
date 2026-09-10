"""Asset manual maintenance: create + remap with ticket redispatch."""

from __future__ import annotations

from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.assets.dispatch import get_current_owner
from apps.assets.models import AssetOwnerMap
from apps.tickets.models import TicketState, VulnTicket

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


@pytest.fixture
def asset_db(db: Any) -> dict[str, User]:
    return {
        "operator": _make_user("as_operator", Role.OPERATOR),
        "owner_a": _make_user("as_owner_a", Role.OWNER),
        "owner_b": _make_user("as_owner_b", Role.OWNER),
        "owner": _make_user("as_plain_owner", Role.OWNER),
    }


@pytest.mark.django_db
def test_create_with_owner_redispatches(asset_db: dict[str, User]) -> None:
    now = timezone.now()
    VulnTicket.objects.create(
        dedup_key="asset-write-001",
        ip="10.60.0.9",
        port=443,
        protocol="tcp",
        severity="高",
        state=TicketState.PENDING_FIX,
        first_seen_at=now,
        last_seen_at=now,
        sla_due_at=now + timezone.timedelta(days=30),
    )
    resp = _auth("as_operator").post(
        "/api/assets",
        {"ip": "10.60.0.9", "hostname": "offline-web", "owner": "as_owner_a"},
        format="json",
    )
    assert resp.status_code == 201, resp.content
    assert resp.data["owner"] == "as_owner_a"
    assert resp.data["remapped"] == 1
    assert get_current_owner("10.60.0.9") == asset_db["owner_a"]
    assert VulnTicket.objects.get(dedup_key="asset-write-001").assignee == asset_db["owner_a"]


@pytest.mark.django_db
def test_create_duplicate_and_bad_ip_400(asset_db: dict[str, User]) -> None:
    client = _auth("as_operator")
    assert client.post("/api/assets", {"ip": "10.60.0.10"}, format="json").status_code == 201
    assert client.post("/api/assets", {"ip": "10.60.0.10"}, format="json").status_code == 400
    assert client.post("/api/assets", {"ip": "not-an-ip"}, format="json").status_code == 400
    assert client.post("/api/assets", {}, format="json").status_code == 400


@pytest.mark.django_db
def test_remap_moves_owner_and_tickets(asset_db: dict[str, User]) -> None:
    client = _auth("as_operator")
    client.post("/api/assets", {"ip": "10.60.0.11", "owner": "as_owner_a"}, format="json")
    resp = client.post(
        "/api/assets/remap", {"ip": "10.60.0.11", "username": "as_owner_b"}, format="json"
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["owner"] == "as_owner_b"
    assert get_current_owner("10.60.0.11") == asset_db["owner_b"]
    assert AssetOwnerMap.objects.filter(ip_id="10.60.0.11").count() == 2
    resp = client.post("/api/assets/remap", {"ip": "10.60.0.11", "username": ""}, format="json")
    assert resp.status_code == 200
    assert resp.data["owner"] is None
    assert get_current_owner("10.60.0.11") is None


@pytest.mark.django_db
def test_remap_unknown_asset_and_user_404(asset_db: dict[str, User]) -> None:
    client = _auth("as_operator")
    assert client.post("/api/assets/remap", {"ip": "10.60.0.99"}, format="json").status_code == 404
    client.post("/api/assets", {"ip": "10.60.0.12"}, format="json")
    assert (
        client.post(
            "/api/assets/remap", {"ip": "10.60.0.12", "username": "ghost"}, format="json"
        ).status_code
        == 404
    )


@pytest.mark.django_db
def test_write_owner_forbidden(asset_db: dict[str, User]) -> None:
    client = _auth("as_plain_owner")
    assert client.post("/api/assets", {"ip": "10.60.0.13"}, format="json").status_code == 403
    assert client.post("/api/assets/remap", {"ip": "10.60.0.13"}, format="json").status_code == 403
