"""P0-2: asset CSV import (dry-run, apply, user provisioning, dispatch)."""

from __future__ import annotations

import io
import uuid
from typing import Any

import openpyxl
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import DeptLeaderMap, Role, User
from apps.assets.models import Asset, AssetOwnerMap
from apps.tickets.models import TicketState, VulnTicket

PW: str = "pw-asset-test-123"
CSV_OK: str = (
    "ip,hostname,os,biz_system,owner,owner_dept,email,wecom_userid\n"
    "10.40.0.1,web-1,linux,OA,zhangsan,运维部,zhangsan@example.com,zhangsan\n"
    "10.40.0.2,db-1,linux,财务,lisi,财务部,,\n"
)
CSV_CN: str = "IP地址,主机名,负责人\n10.40.0.3,app-1,wangwu\n"
# 服务器资源汇总表.xlsx 列序
CSV_NEW_FMT: str = (
    "管理人,管理人-隶属组织,资源使用部门,部门负责人,内网IP\n"
    "解童钧(12047),平台与医技-数据平台中心,平台与医技-数据平台中心,廖凯旋(11540),172.17.1.93\n"
    "郁亦男(3313),IHS创新-IHS创新研发中心,IHS创新-IHS创新研发中心,黄智勇(854),172.16.0.114\n"
)


def _auth_op() -> APIClient:
    User.objects.create_user(
        username="asset_op", password=PW, wecom_userid="asset_op",
        role=Role.OPERATOR,
    )
    client = APIClient()
    login = client.post(
        "/api/auth/local", {"username": "asset_op", "password": PW}, format="json"
    )
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


def _upload(client: APIClient, text: str, dry_run: bool) -> Any:
    f = SimpleUploadedFile("assets.csv", text.encode("utf-8"), content_type="text/csv")
    suffix = "?dry_run=true" if dry_run else ""
    return client.post(f"/api/imports/assets{suffix}", {"file": f}, format="multipart")


def _xlsx_upload(client: APIClient, rows: list[list[str]], dry_run: bool) -> Any:
    wb = openpyxl.Workbook()
    ws = wb.active
    assert ws is not None
    for row in rows:
        ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    f = SimpleUploadedFile(
        "服务器资源汇总表.xlsx", buf.getvalue(), content_type="application/octet-stream"
    )
    suffix = "?dry_run=true" if dry_run else ""
    return client.post(f"/api/imports/assets{suffix}", {"file": f}, format="multipart")


@pytest.mark.django_db
def test_asset_template_and_dry_run() -> None:
    client = _auth_op()
    tpl = client.get("/api/imports/assets/template")
    assert tpl.status_code == 200
    assert "管理人" in tpl.content.decode()
    resp = _upload(client, CSV_OK, dry_run=True)
    assert resp.status_code == 200, resp.content
    assert resp.data["applied"] is False
    assert resp.data["valid"] == 2
    assert Asset.objects.count() == 0


@pytest.mark.django_db
def test_asset_apply_provisions_and_dispatches() -> None:
    client = _auth_op()
    now = timezone.now()
    VulnTicket.objects.create(
        dedup_key=uuid.uuid4().hex, ip="10.40.0.1", port=443, protocol="tcp",
        plugin_id="RSAS-A-1", plugin_name="资产派单测试",
        severity="高", state=TicketState.PENDING_ASSIGN,
        first_seen_at=now, last_seen_at=now,
        sla_due_at=now + timezone.timedelta(days=30),
    )
    resp = _upload(client, CSV_OK, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    body = resp.data
    assert body["created_assets"] == 2
    assert body["dispatched"] == 1
    assert {u["username"] for u in body["created_users"]} == {"zhangsan", "lisi"}
    assert all(u["temp_password"] for u in body["created_users"])
    zhangsan = User.objects.get(username="zhangsan")
    assert zhangsan.email == "zhangsan@example.com"
    assert zhangsan.wecom_userid == "zhangsan"
    ticket = VulnTicket.objects.get(ip="10.40.0.1")
    assert ticket.assignee == zhangsan

    resp2 = _upload(client, CSV_CN, dry_run=False)
    assert resp2.status_code in (200, 201), resp2.content
    assert AssetOwnerMap.objects.filter(ip_id="10.40.0.3").exists()


@pytest.mark.django_db
def test_asset_remap_keeps_history() -> None:
    client = _auth_op()
    _upload(client, CSV_OK, dry_run=False)
    swap = "ip,owner\n10.40.0.1,lisi\n"
    resp = _upload(client, swap, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    assert resp.data["remapped"] == 1
    assert AssetOwnerMap.objects.filter(ip_id="10.40.0.1").count() == 2


@pytest.mark.django_db
def test_asset_missing_columns_400() -> None:
    client = _auth_op()
    resp = _upload(client, "hostname,os\na,linux\n", dry_run=False)
    assert resp.status_code == 400


@pytest.mark.django_db
def test_asset_missing_ip_column_400() -> None:
    client = _auth_op()
    resp = _upload(client, "管理人,资源使用部门\n张三,A部门\n", dry_run=False)
    assert resp.status_code == 400
    assert "ip" in str(resp.data["errors"])


@pytest.mark.django_db
def test_asset_new_format_csv_import() -> None:
    client = _auth_op()
    now = timezone.now()
    VulnTicket.objects.create(
        dedup_key=uuid.uuid4().hex, ip="172.17.1.93", port=443, protocol="tcp",
        plugin_id="RSAS-N-1", plugin_name="新格式派单测试",
        severity="高", state=TicketState.PENDING_ASSIGN,
        first_seen_at=now, last_seen_at=now,
        sla_due_at=now + timezone.timedelta(days=30),
    )
    resp = _upload(client, CSV_NEW_FMT, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    body = resp.data
    assert body["created_assets"] == 2
    assert body["dispatched"] == 1
    assert body["created_leaders"] == 2
    assert body["leader_dept_maps"] == 2

    manager = User.objects.get(wecom_userid="12047")
    assert manager.username == "解童钧"
    assert manager.role == Role.OWNER
    assert manager.dept == "平台与医技-数据平台中心"
    leader = User.objects.get(wecom_userid="11540")
    assert leader.username == "廖凯旋"
    assert leader.role == Role.LEADER
    assert leader.dept == "平台与医技-数据平台中心"

    asset = Asset.objects.get(ip="172.17.1.93")
    assert asset.biz_system == "平台与医技-数据平台中心"
    current = asset.owner_history.filter(valid_to=None).first()
    assert current is not None and current.user_id == manager.pk
    assert DeptLeaderMap.objects.filter(user=leader, dept_path="平台与医技-数据平台中心").exists()
    assert DeptLeaderMap.objects.filter(
        user=User.objects.get(wecom_userid="854"), dept_path="IHS创新-IHS创新研发中心"
    ).exists()


@pytest.mark.django_db
def test_asset_new_format_xlsx_import() -> None:
    client = _auth_op()
    rows = [
        ["管理人", "管理人-隶属组织", "资源使用部门", "部门负责人", "内网IP"],
        ["王文博(3510)", "陕甘青区域-实施服务部", "陕甘青区域-实施服务部", "韩杰(14538)", "172.17.0.95"],
        ["朱艳波(12077)", None, "售前咨询总部", None, "172.17.0.93"],
    ]
    resp = _xlsx_upload(client, rows, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    manager = User.objects.get(wecom_userid="3510")
    assert manager.dept == "陕甘青区域-实施服务部"
    assert User.objects.filter(wecom_userid="14538", role=Role.LEADER).exists()
    asset = Asset.objects.get(ip="172.17.0.93")
    assert asset.biz_system == "售前咨询总部"
    asset95 = Asset.objects.get(ip="172.17.0.95")
    assert asset95.owner_history.filter(valid_to=None, user=manager).exists()
    assert DeptLeaderMap.objects.filter(dept_path="售前咨询总部").count() == 0

    dry = _xlsx_upload(client, rows, dry_run=True)
    assert dry.status_code == 200, dry.content
    assert dry.data["valid"] == 2


@pytest.mark.django_db
def test_asset_person_name_and_role_collision() -> None:
    client = _auth_op()
    rows = [
        ["管理人", "管理人-隶属组织", "资源使用部门", "部门负责人", "内网IP"],
        ["张三(111)", "部门A", "部门A", "张三(222)", "10.9.0.1"],
    ]
    resp = _xlsx_upload(client, rows, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    users = User.objects.filter(username__in=["张三", "张三(222)"])
    assert users.count() == 2
    leader = User.objects.get(wecom_userid="222")
    assert leader.username == "张三(222)"
    assert leader.role == Role.LEADER

    promote = "ip,owner,owner_dept,dept_leader,use_dept\n10.9.0.2,李四,部门B,李四,部门B\n"
    resp2 = _upload(client, promote, dry_run=False)
    assert resp2.status_code in (200, 201), resp2.content
    lisi = User.objects.get(username="李四")
    assert lisi.role == Role.LEADER
    assert DeptLeaderMap.objects.filter(user=lisi, dept_path="部门B").exists()


@pytest.mark.django_db
def test_asset_new_format_does_not_blank_missing_columns() -> None:
    client = _auth_op()
    _upload(client, "ip,hostname,os,biz_system,owner\n10.40.0.9,web-9,linux,OA,zhang\n", dry_run=False)
    rows = [
        ["管理人", "资源使用部门", "内网IP"],
        ["张三三(555)", "新部门", "10.40.0.9"],
    ]
    resp = _xlsx_upload(client, rows, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    asset = Asset.objects.get(ip="10.40.0.9")
    assert asset.hostname == "web-9"
    assert asset.os == "linux"
    assert asset.biz_system == "新部门"


SYNC_V1: str = (
    "管理人,资源使用部门,部门负责人,内网IP\n"
    "张三(111),部门A,王五(333),10.50.0.1\n"
    "李四(222),部门B,赵六(444),10.50.0.2\n"
)
SYNC_V2: str = (
    "管理人,资源使用部门,部门负责人,内网IP\n"
    "张三(111),部门A,王五(333),10.50.0.1\n"
)


@pytest.mark.django_db
def test_asset_sync_orphans_and_rebuilds() -> None:
    client = _auth_op()
    resp1 = _upload(client, SYNC_V1, dry_run=False)
    assert resp1.status_code in (200, 201), resp1.content
    assert resp1.data["sync"] is True
    assert AssetOwnerMap.objects.filter(ip_id="10.50.0.2", valid_to=None).exists()
    assert DeptLeaderMap.objects.filter(dept_path="部门B").exists()

    dry2 = _upload(client, SYNC_V2, dry_run=True)
    assert dry2.status_code == 200, dry2.content
    assert dry2.data["sync"] is True
    assert dry2.data["orphaned_preview"] == 1

    resp2 = _upload(client, SYNC_V2, dry_run=False)
    assert resp2.status_code in (200, 201), resp2.content
    assert resp2.data["orphaned"] == 1
    assert resp2.data["leader_maps_rebuilt"] is True
    assert resp2.data["leader_dept_maps"] == 1
    assert not AssetOwnerMap.objects.filter(ip_id="10.50.0.2", valid_to=None).exists()
    assert Asset.objects.filter(ip="10.50.0.2").exists()  # 资产保留，仅置无主
    assert AssetOwnerMap.objects.filter(ip_id="10.50.0.2", valid_to=None).count() == 0
    assert DeptLeaderMap.objects.filter(dept_path="部门A", user__username="王五").exists()
    assert not DeptLeaderMap.objects.filter(dept_path="部门B").exists()


@pytest.mark.django_db
def test_asset_legacy_csv_not_sync() -> None:
    client = _auth_op()
    _upload(client, SYNC_V1, dry_run=False)
    legacy = "ip,owner\n10.50.0.9,zhangsan\n"
    resp = _upload(client, legacy, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    assert resp.data["sync"] is False
    assert resp.data["orphaned"] == 0
    assert resp.data["leader_maps_rebuilt"] is False
    assert AssetOwnerMap.objects.filter(ip_id="10.50.0.1", valid_to=None).exists()
    assert AssetOwnerMap.objects.filter(ip_id="10.50.0.2", valid_to=None).exists()
    assert DeptLeaderMap.objects.filter(dept_path="部门B").exists()
