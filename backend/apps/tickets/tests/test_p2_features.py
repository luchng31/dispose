"""P2: SLA policy admin endpoints, dashboard by_dept, 工号-only asset import."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.assets.models import Asset, AssetOwnerMap
from apps.tickets.models import Severity, SlaPolicy, TicketState, VulnTicket
from apps.tickets.sla import compute_due

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
        "plugin_id": "RSAS-P2-001",
        "plugin_name": "P2 测试插件",
        "severity": Severity.HIGH,
        "state": state,
        "first_seen_at": now,
        "last_seen_at": now,
        "sla_due_at": now + timezone.timedelta(days=30),
    }
    params.update(kwargs)
    return VulnTicket.objects.create(**params)


@pytest.mark.django_db
def test_sla_policies_get_merges_fallback() -> None:
    _make_user("sla_admin", Role.ADMIN)
    client = _auth("sla_admin")
    SlaPolicy.objects.all().delete()
    resp = client.get("/api/ops/sla-policies")
    assert resp.status_code == 200
    rows = {r["severity"]: r for r in resp.data["results"]}
    assert set(rows) == {"严重", "高", "中", "低"}
    assert rows["严重"]["days"] == 7 and rows["严重"]["source"] == "fallback"
    SlaPolicy.objects.create(severity="严重", days=3, warn_days_before=1)
    resp2 = _auth("sla_admin").get("/api/ops/sla-policies")
    row = {r["severity"]: r for r in resp2.data["results"]}["严重"]
    assert row["days"] == 3 and row["source"] == "table"


@pytest.mark.django_db
def test_sla_policy_put_updates_compute_due() -> None:
    _make_user("sla_admin2", Role.ADMIN)
    client = _auth("sla_admin2")
    resp = client.put(
        "/api/ops/sla-policies/高", {"days": 14, "warn_days_before": 5}, format="json"
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["days"] == 14 and resp.data["source"] == "table"
    from apps.tickets.sla import sla_days_for, warn_days_for

    assert sla_days_for("高") == 14
    assert warn_days_for("高") == 5
    fresh = _make_ticket("10.66.0.1", TicketState.PENDING_ASSIGN)
    fresh.sla_due_at = compute_due(fresh.first_seen_at, "高")  # type: ignore[arg-type]
    assert (fresh.sla_due_at - fresh.first_seen_at).days == 14  # type: ignore[operator]


@pytest.mark.django_db
def test_sla_policy_admin_only() -> None:
    _make_user("sla_operator", Role.OPERATOR)
    _make_user("sla_admin3", Role.ADMIN)
    client = _auth("sla_operator")
    assert client.get("/api/ops/sla-policies").status_code == 403
    assert client.put("/api/ops/sla-policies/高", {"days": 10}, format="json").status_code == 403
    admin = _auth("sla_admin3")
    assert admin.put("/api/ops/sla-policies/高", {"days": 10}, format="json").status_code == 200
    assert admin.put("/api/ops/sla-policies/不存在", {"days": 10}, format="json").status_code == 400
    assert admin.put("/api/ops/sla-policies/高", {"days": 0}, format="json").status_code == 400


@pytest.mark.django_db
def test_dashboard_by_dept_top_level_grouping() -> None:
    owner_a = _make_user("db_owner_a", Role.OWNER, dept="研发中心/一组")
    owner_b = _make_user("db_owner_b", Role.OWNER, dept="研发中心/二组")
    owner_c = _make_user("db_owner_c", Role.OWNER, dept="运营部")
    owner_d = _make_user("db_owner_d", Role.OWNER, dept="平台与医技-数据平台中心-数据应用研发部")
    now = timezone.now()
    _make_ticket("10.77.0.1", TicketState.PENDING_FIX, assignee=owner_a,
                 sla_due_at=now - timezone.timedelta(days=1))
    _make_ticket("10.77.0.2", TicketState.PENDING_FIX, assignee=owner_b)
    _make_ticket("10.77.0.3", TicketState.CLOSED, assignee=owner_b)
    _make_ticket("10.77.0.4", TicketState.PENDING_FIX, assignee=owner_c)
    _make_ticket("10.77.0.5", TicketState.PENDING_ASSIGN)
    _make_ticket("10.77.0.6", TicketState.PENDING_FIX, assignee=owner_d)
    _make_user("db_operator", Role.OPERATOR)
    client = _auth("db_operator")
    resp = client.get("/api/dashboard")
    assert resp.status_code == 200
    by_dept = resp.data["by_dept"]
    assert by_dept["研发中心"]["total"] == 3
    assert by_dept["研发中心"]["open"] == 2
    assert by_dept["研发中心"]["closed"] == 1
    assert by_dept["研发中心"]["overdue"] == 1
    assert by_dept["运营部"]["total"] == 1
    assert by_dept["未分配"]["total"] == 1
    assert by_dept["平台与医技"]["total"] == 1
    prefix = client.get("/api/dashboard", {"dept_prefix": "研发中心"})
    assert prefix.data["total"] == 3
    hyphen_prefix = client.get("/api/dashboard", {"dept_prefix": "平台与医技"})
    assert hyphen_prefix.data["total"] == 1
    exact = client.get("/api/dashboard", {"dept": "研发中心/一组"})
    assert exact.data["total"] == 1


@pytest.mark.django_db
def test_asset_import_wecom_id_only_row() -> None:
    _make_user("imp_operator", Role.OPERATOR)
    csv_body = "ip,wecom_userid\n10.88.0.1,10086\n10.88.0.2,zhang_san\n"
    from django.core.files.uploadedfile import SimpleUploadedFile

    client = _auth("imp_operator")
    resp = client.post(
        "/api/imports/assets",
        {"file": SimpleUploadedFile("assets.csv", csv_body.encode("utf-8"), "text/csv")},
        format="multipart",
    )
    assert resp.status_code == 201, resp.content
    assert resp.data["errors"] == []
    user = User.objects.filter(wecom_userid="10086").first()
    assert user is not None
    assert user.username == "10086"
    asset = Asset.objects.filter(ip="10.88.0.1").first()
    assert asset is not None
    current = asset.owner_history.filter(valid_to__isnull=True).first()
    assert current is not None and current.user_id == user.pk
    user2 = User.objects.filter(wecom_userid="zhang_san").first()
    assert user2 is not None
    assert AssetOwnerMap.objects.filter(user=user2).exists()
