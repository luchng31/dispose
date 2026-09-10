"""P1 ops extras: pool CSV export, batch assign, deactivate-unassign,
user-admin audit rows, WeCom bot notify."""

from __future__ import annotations

import json
import urllib.request
import uuid
from typing import Any
from unittest import mock

import pytest
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.audit.models import AuditLog
from apps.tickets.models import Severity, TicketState, VulnTicket

PW: str = "pw-test-only-123"


def _make_user(username: str, role: str, **kwargs: Any) -> User:
    return User.objects.create_user(  # type: ignore[arg-type]
        username=username, password=PW, wecom_userid=username, role=role, **kwargs
    )


def _auth(username: str) -> APIClient:
    client = APIClient()
    login = client.post(
        "/api/auth/local", {"username": username, "password": PW}, format="json"
    )
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


def _make_ticket(ip: str, state: str = TicketState.PENDING_FIX, **kwargs: Any) -> VulnTicket:
    now = timezone.now()
    params: dict[str, Any] = {
        "dedup_key": uuid.uuid4().hex,
        "ip": ip,
        "port": 443,
        "protocol": "tcp",
        "plugin_id": "RSAS-P1-001",
        "plugin_name": "P1 测试插件",
        "severity": Severity.HIGH,
        "state": state,
        "first_seen_at": now,
        "last_seen_at": now,
        "sla_due_at": now + timezone.timedelta(days=30),
    }
    params.update(kwargs)
    return VulnTicket.objects.create(**params)


@pytest.mark.django_db
def test_pool_export_csv_bom_and_rows() -> None:
    operator = _make_user("ex_operator", Role.OPERATOR)
    _make_ticket("10.99.0.1", TicketState.PENDING_FIX, assignee=operator)
    client = _auth("ex_operator")
    resp = client.get("/api/ops/pool/export")
    assert resp.status_code == 200
    body = resp.content.decode("utf-8-sig")
    assert body.startswith("﻿") or resp.content.startswith(b"\xef\xbb\xbf")
    assert "ID,IP,端口,严重性,状态" in body
    assert "10.99.0.1" in body
    assert resp["Content-Disposition"].endswith("pool_export.csv\"")


@pytest.mark.django_db
def test_pool_export_owner_403() -> None:
    _make_user("ex_owner", Role.OWNER)
    client = _auth("ex_owner")
    assert client.get("/api/ops/pool/export").status_code == 403


@pytest.mark.django_db
def test_batch_assign_mixed_states() -> None:
    _make_user("ba_operator", Role.OPERATOR)
    owner = _make_user("ba_owner", Role.OWNER)
    t1 = _make_ticket("10.99.1.1", TicketState.PENDING_ASSIGN)
    t2 = _make_ticket("10.99.1.2", TicketState.PENDING_FIX)
    t3 = _make_ticket("10.99.1.3", TicketState.CLOSED)
    client = _auth("ba_operator")
    resp = client.post(
        "/api/ops/batch-assign",
        {"ids": [t1.pk, t2.pk, t3.pk], "assignee": "ba_owner"},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["assigned"] == 2
    assert resp.data["skipped"] == [{"id": t3.pk, "reason": "状态已闭合不可派单"}]
    t1.refresh_from_db()
    t2.refresh_from_db()
    assert t1.state == TicketState.PENDING_FIX
    assert t1.assignee == owner
    assert t2.assignee == owner


@pytest.mark.django_db
def test_batch_assign_unknown_user_404() -> None:
    _make_user("ba_operator2", Role.OPERATOR)
    t1 = _make_ticket("10.99.2.1", TicketState.PENDING_ASSIGN)
    client = _auth("ba_operator2")
    resp = client.post(
        "/api/ops/batch-assign", {"ids": [t1.pk], "assignee": "ghost"}, format="json"
    )
    assert resp.status_code == 404


@pytest.mark.parametrize(
    "payload,status_code",
    [({"ids": [], "assignee": "x"}, 400), ({"ids": ["abc"], "assignee": "x"}, 400),
     ({"ids": list(range(501))}, 400)],
)
@pytest.mark.django_db
def test_batch_assign_bad_payload_400(payload: dict[str, Any], status_code: int) -> None:
    _make_user("ba_operator3", Role.OPERATOR)
    _make_user("x", Role.OWNER)
    client = _auth("ba_operator3")
    resp = client.post("/api/ops/batch-assign", payload, format="json")
    assert resp.status_code == status_code


@pytest.mark.django_db
def test_deactivate_user_unassigns_open_tickets_and_audits() -> None:
    _make_user("da_operator", Role.OPERATOR)
    owner = _make_user("da_owner", Role.OWNER)
    open_t = _make_ticket("10.99.3.1", TicketState.PENDING_FIX, assignee=owner)
    closed_t = _make_ticket("10.99.3.2", TicketState.CLOSED, assignee=owner)
    client = _auth("da_operator")
    resp = client.patch(
        "/api/ops/admin/users/da_owner", {"is_active": False}, format="json"
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["unassigned_open_tickets"] == 1
    open_t.refresh_from_db()
    closed_t.refresh_from_db()
    assert open_t.assignee is None
    assert closed_t.assignee == owner
    assert AuditLog.objects.filter(action="user.deactivate", entity_id="da_owner").exists()


@pytest.mark.django_db
def test_cannot_deactivate_self() -> None:
    _make_user("self_operator", Role.OPERATOR)
    client = _auth("self_operator")
    resp = client.patch(
        "/api/ops/admin/users/self_operator", {"is_active": False}, format="json"
    )
    assert resp.status_code == 400


@pytest.mark.django_db
def test_user_create_and_reset_audited() -> None:
    _make_user("aud_operator", Role.OPERATOR)
    client = _auth("aud_operator")
    resp = client.post(
        "/api/ops/admin/users",
        {"username": "aud_new_user", "role": "owner"},
        format="json",
    )
    assert resp.status_code == 201
    resp2 = client.post("/api/ops/admin/users/aud_new_user", {}, format="json")
    assert resp2.status_code == 200
    assert AuditLog.objects.filter(action="user.create", entity_id="aud_new_user").exists()
    assert AuditLog.objects.filter(
        action="user.reset_password", entity_id="aud_new_user"
    ).exists()


@pytest.mark.django_db
@override_settings(NOTIFY_WECOM_WEBHOOK="https://example.invalid/webhook")
def test_wecom_test_channel_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    _make_user("wc_operator", Role.OPERATOR)
    captured: dict[str, Any] = {}

    def fake_urlopen(req: urllib.request.Request, timeout: float) -> Any:
        captured["url"] = req.full_url
        captured["payload"] = json.loads(req.data.decode())
        return mock.MagicMock(__enter__=lambda s: mock.MagicMock(
            read=lambda: b'{"errcode":0,"errmsg":"ok"}'
        ))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = _auth("wc_operator")
    resp = client.post("/api/ops/notify/test", {"channel": "wecom"}, format="json")
    assert resp.status_code == 200
    assert resp.data["sent"] == 1
    assert captured["url"] == "https://example.invalid/webhook"
    assert "测试" in captured["payload"]["text"]["content"]


@pytest.mark.django_db
def test_notify_status_reports_wecom() -> None:
    _make_user("st_operator", Role.OPERATOR)
    client = _auth("st_operator")
    resp = client.get("/api/ops/notify/status")
    assert resp.status_code == 200
    assert "wecom_configured" in resp.data
