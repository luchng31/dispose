"""GET /api/assets/overview: role-scoped IP allocation visibility."""

from __future__ import annotations

from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import DeptLeaderMap, Role, User
from apps.assets.models import Asset, AssetOwnerMap

PW: str = "pw-overview-test-123"


def _make_user(username: str, role: str, **kwargs: Any) -> User:
    return User.objects.create_user(
        username=username, password=PW, wecom_userid=username, role=role, **kwargs
    )


def _auth(username: str) -> APIClient:
    client = APIClient()
    login = client.post("/api/auth/local", {"username": username, "password": PW}, format="json")
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


def _asset(ip: str, dept: str = "", owner: User | None = None) -> Asset:
    asset = Asset.objects.create(ip=ip, biz_system=dept)
    if owner is not None:
        AssetOwnerMap.objects.create(
            ip=asset, user=owner, valid_from=timezone.now(), valid_to=None
        )
    return asset


@pytest.mark.django_db
def test_overview_requires_auth() -> None:
    client = APIClient()
    resp = client.get("/api/assets/overview")
    assert resp.status_code == 403


@pytest.mark.django_db
def test_overview_leader_sees_only_managed_depts() -> None:
    op = _make_user("ov_op", Role.OPERATOR)
    leader = _make_user("ov_leader", Role.LEADER)
    DeptLeaderMap.objects.create(user=leader, dept_path="平台与医技-医技中心")
    DeptLeaderMap.objects.create(user=leader, dept_path="IHS创新")
    in_dept = _asset("10.1.0.1", dept="平台与医技-医技中心", owner=op)
    sibling = _asset("10.1.0.2", dept="IHS创新-IHS研发中心")
    outside = _asset("10.1.0.3", dept="基础业务")
    _asset("10.1.0.4", dept="平台与医技-医技中心-检查中心")

    client = _auth("ov_leader")
    resp = client.get("/api/assets/overview")
    assert resp.status_code == 200, resp.content
    ips = {row["ip"] for row in resp.data["results"]}
    assert ips == {in_dept.ip, sibling.ip, "10.1.0.4"}
    assert resp.data["scope"] == "dept"

    row = next(r for r in resp.data["results"] if r["ip"] == in_dept.ip)
    assert row["owner"] == "ov_op"
    assert row["owner_dept"] == ""
    assert row["dept"] == "平台与医技-医技中心"
    assert row["dept_leader"] == "ov_leader"
    assert outside.ip not in ips

    q = client.get("/api/assets/overview", {"q": "10.1.0.1"})
    assert [r["ip"] for r in q.data["results"]] == ["10.1.0.1"]
    prefix = client.get("/api/assets/overview", {"dept": "平台与医技-医技中心-"})
    assert {r["ip"] for r in prefix.data["results"]} == {"10.1.0.4"}


@pytest.mark.django_db
def test_overview_owner_sees_own_ips_operator_sees_all() -> None:
    owner = _make_user("ov_owner", Role.OWNER, dept="研发部")
    other = _make_user("ov_owner2", Role.OWNER)
    mine = _asset("10.2.0.1", dept="研发部", owner=owner)
    _asset("10.2.0.2", dept="研发部", owner=other)
    orphan = _asset("10.2.0.3", dept="研发部")

    client = _auth("ov_owner")
    resp = client.get("/api/assets/overview")
    assert resp.data["scope"] == "own"
    assert {r["ip"] for r in resp.data["results"]} == {mine.ip}
    assert resp.data["results"][0]["owner_dept"] == "研发部"

    _make_user("ov_op2", Role.OPERATOR)
    op_client = _auth("ov_op2")
    all_resp = op_client.get("/api/assets/overview")
    assert all_resp.data["scope"] == "all"
    assert {r["ip"] for r in all_resp.data["results"]} == {mine.ip, "10.2.0.2", orphan.ip}
    assert all_resp.data["count"] == 3


@pytest.mark.django_db
def test_overview_leader_without_maps_is_empty() -> None:
    _make_user("ov_leader2", Role.LEADER)
    _asset("10.3.0.1", dept="某部门")
    client = _auth("ov_leader2")
    resp = client.get("/api/assets/overview")
    assert resp.status_code == 200
    assert resp.data["count"] == 0
    assert resp.data["results"] == []


@pytest.mark.django_db
def test_overview_pagination() -> None:
    _make_user("ov_op3", Role.OPERATOR)
    for i in range(1, 6):
        _asset(f"10.4.0.{i}", dept="部门P")
    client = _auth("ov_op3")
    resp = client.get("/api/assets/overview", {"page": 2, "page_size": 2})
    assert resp.status_code == 200
    assert resp.data["count"] == 5
    assert resp.data["page"] == 2
    assert resp.data["page_size"] == 2
    assert [r["ip"] for r in resp.data["results"]] == ["10.4.0.3", "10.4.0.4"]
    assert resp.data["scope"] == "all"
    big = client.get("/api/assets/overview", {"page": 1, "page_size": 500})
    assert big.data["page_size"] == 100
    assert len(big.data["results"]) == 5
    beyond = client.get("/api/assets/overview", {"page": 9, "page_size": 2})
    assert beyond.data["results"] == []
    assert beyond.data["count"] == 5
    bad = client.get("/api/assets/overview", {"page": "x", "page_size": "y"})
    assert bad.data["page"] == 1
    assert bad.data["page_size"] == 20
