"""Batch close / ignore: per-ticket transition with skip reasons.

Mirrors batch-assign shape ({closed|ignored, skipped[{id, reason}]});
illegal edges never abort the batch.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
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


def _make_ticket(ip: str, state: str, **kwargs: Any) -> VulnTicket:
    now = timezone.now()
    params: dict[str, Any] = {
        "dedup_key": uuid.uuid4().hex,
        "ip": ip,
        "port": 443,
        "protocol": "tcp",
        "plugin_id": "RSAS-BATCH-001",
        "plugin_name": "演示漏洞",
        "severity": Severity.HIGH,
        "state": state,
        "first_seen_at": now,
        "last_seen_at": now,
        "sla_due_at": now + timezone.timedelta(days=30),
    }
    params.update(kwargs)
    return VulnTicket.objects.create(**params)


@pytest.fixture
def batch_db(db: Any) -> dict[str, int]:
    _make_user("bo_operator", Role.OPERATOR)
    _make_user("bo_owner", Role.OWNER)
    ok = _make_ticket("10.50.0.1", TicketState.PENDING_RETEST)
    bad = _make_ticket("10.50.0.1", TicketState.PENDING_FIX)
    return {"ok": ok.pk, "bad": bad.pk}


@pytest.mark.django_db
def test_batch_close_mixed(batch_db: dict[str, int]) -> None:
    resp = _auth("bo_operator").post(
        "/api/ops/batch-close",
        {"ids": [batch_db["ok"], batch_db["bad"]], "note": "HW 误报批量关闭"},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["closed"] == 1
    assert [s["id"] for s in resp.data["skipped"]] == [batch_db["bad"]]
    assert VulnTicket.objects.get(pk=batch_db["ok"]).state == TicketState.CLOSED
    assert VulnTicket.objects.get(pk=batch_db["bad"]).state == TicketState.PENDING_FIX


@pytest.mark.django_db
def test_batch_ignore_requires_reason(batch_db: dict[str, int]) -> None:
    client = _auth("bo_operator")
    assert client.post("/api/ops/batch-ignore", {"ids": [batch_db["bad"]]}, format="json").status_code == 422
    resp = client.post(
        "/api/ops/batch-ignore",
        {"ids": [batch_db["ok"], batch_db["bad"]], "reason": "HW 误报"},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["ignored"] == 2
    assert resp.data["skipped"] == []


@pytest.mark.django_db
def test_batch_bad_payload_400(batch_db: dict[str, int]) -> None:
    client = _auth("bo_operator")
    assert client.post("/api/ops/batch-close", {"ids": []}, format="json").status_code == 400
    assert client.post("/api/ops/batch-close", {"ids": ["x"]}, format="json").status_code == 400


@pytest.mark.django_db
def test_batch_owner_forbidden(batch_db: dict[str, int]) -> None:
    client = _auth("bo_owner")
    assert client.post("/api/ops/batch-close", {"ids": [batch_db["ok"]]}, format="json").status_code == 403
    assert (
        client.post(
            "/api/ops/batch-ignore", {"ids": [batch_db["ok"]], "reason": "x"}, format="json"
        ).status_code
        == 403
    )
