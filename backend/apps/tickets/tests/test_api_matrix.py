"""Task6 RED: RBAC x endpoint matrix for the tickets/ops/dashboard/audit API.

Covers: owner sees only mine + pool 403, auditor POST 403, non-operator
close 403, illegal submit 422, dashboard numbers reconcile with ticket
queries, audit filters work. DB_ENGINE=sqlite.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.assets.models import Asset, AssetOwnerMap
from apps.audit.models import AuditLog
from apps.imports.models import BatchSource, ScanBatch
from apps.tickets.models import Severity, TicketState, VulnTicket

PW: str = "pw-test-only-123"


def _make_user(username: str, role: str, **kwargs: Any) -> User:
    params: dict[str, Any] = {
        "username": username,
        "password": PW,
        "wecom_userid": username,
        "role": role,
    }
    params.update(kwargs)
    user: User = User.objects.create_user(**params)  # type: ignore[arg-type]
    return user


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


def _make_ticket(ip: str, state: str = TicketState.PENDING_FIX, **kwargs: Any) -> VulnTicket:
    now = timezone.now()
    params: dict[str, Any] = {
        "dedup_key": uuid.uuid4().hex,
        "ip": ip,
        "port": 443,
        "protocol": "tcp",
        "plugin_id": "RSAS-MATRIX-001",
        "plugin_name": "OpenSSL CCS 注入",
        "severity": Severity.HIGH,
        "state": state,
        "first_seen_at": now,
        "last_seen_at": now,
        "sla_due_at": now + timezone.timedelta(days=30),
    }
    params.update(kwargs)
    return VulnTicket.objects.create(**params)


@pytest.fixture
def matrix_db(db: Any) -> dict[str, Any]:
    owner_a: User = _make_user("mx_owner_a", Role.OWNER, dept="biza")
    owner_b: User = _make_user("mx_owner_b", Role.OWNER, dept="bizb")
    operator: User = _make_user("mx_operator", Role.OPERATOR, dept="sec")
    leader: User = _make_user("mx_leader", Role.LEADER, dept="sec")
    auditor: User = _make_user("mx_auditor", Role.AUDITOR, dept="audit")
    admin: User = _make_user("mx_admin", Role.ADMIN, dept="sec")
    Asset.objects.create(ip="10.20.0.1")
    Asset.objects.create(ip="10.20.0.2")
    now = timezone.now()
    AssetOwnerMap.objects.create(ip_id="10.20.0.1", user=owner_a, valid_from=now)
    AssetOwnerMap.objects.create(ip_id="10.20.0.2", user=owner_b, valid_from=now)
    own_fix: VulnTicket = _make_ticket("10.20.0.1", TicketState.PENDING_FIX)
    own_retest: VulnTicket = _make_ticket("10.20.0.1", TicketState.PENDING_RETEST)
    other: VulnTicket = _make_ticket("10.20.0.2", TicketState.PENDING_FIX)
    return {
        "owner_a": owner_a,
        "owner_b": owner_b,
        "operator": operator,
        "leader": leader,
        "auditor": auditor,
        "admin": admin,
        "own_fix": own_fix,
        "own_retest": own_retest,
        "other": other,
    }


@pytest.mark.django_db
def test_owner_my_list_sees_only_mine(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    resp = client.get("/api/tickets/my")
    assert resp.status_code == 200
    assert resp.data["count"] == 2
    assert {row["ip"] for row in resp.data["results"]} == {"10.20.0.1"}
    row = resp.data["results"][0]
    assert set(row) >= {"id", "ip", "port", "title", "severity", "state", "sla_due_at", "assignee", "reopen_count"}


@pytest.mark.django_db
def test_owner_side_hides_ignored(matrix_db: dict[str, Any]) -> None:
    """用户端不显示已忽略工单（低危留痕）：列表/汇总/详情 404；运营仍可见可重开."""
    ignored: VulnTicket = _make_ticket("10.20.0.1", TicketState.IGNORED, assignee=matrix_db["owner_a"])
    owner_client: APIClient = _auth("mx_owner_a")
    listing = owner_client.get("/api/tickets/my")
    assert {row["ip"] for row in listing.data["results"]} == {"10.20.0.1"}
    assert listing.data["count"] == 2  # 已忽略的不在
    assert owner_client.get(f"/api/tickets/{ignored.pk}").status_code == 404
    summary = owner_client.get("/api/tickets/ip-summary")
    row = next(r for r in summary.data["results"] if r["ip"] == "10.20.0.1")
    assert row["total"] == 2  # 汇总同样排除已忽略

    # 运营侧不受影响：池子里可见，详情 200，可重开
    ops_client: APIClient = _auth("mx_operator")
    pool = ops_client.get("/api/ops/pool", {"state": "已忽略"})
    assert pool.data["count"] == 1
    assert ops_client.get(f"/api/tickets/{ignored.pk}").status_code == 200


@pytest.mark.django_db
def test_owner_detail_cross_owner_404(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    other: VulnTicket = matrix_db["other"]
    resp = client.get(f"/api/tickets/{other.pk}")
    assert resp.status_code == 404


@pytest.mark.django_db
def test_owner_detail_own_200_with_timeline(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    own: VulnTicket = matrix_db["own_fix"]
    resp = client.get(f"/api/tickets/{own.pk}")
    assert resp.status_code == 200
    assert resp.data["id"] == own.pk
    assert "fix_evidence" in resp.data
    assert isinstance(resp.data["timeline"], list)


@pytest.mark.django_db
def test_owner_pool_403(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    resp = client.get("/api/ops/pool")
    assert resp.status_code == 403


@pytest.mark.django_db
def test_operator_pool_200_includes_unassigned(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_operator")
    resp = client.get("/api/ops/pool")
    assert resp.status_code == 200
    assert resp.data["count"] == 3
    resp2 = client.get("/api/ops/pool", {"unassigned": "true"})
    assert resp2.status_code == 200
    assert resp2.data["count"] == 3


@pytest.mark.django_db
def test_auditor_post_submit_403(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_auditor")
    own: VulnTicket = matrix_db["own_fix"]
    resp = client.post(f"/api/tickets/{own.pk}/submit", {"evidence": {"note": "x"}}, format="json")
    assert resp.status_code == 403
    get_resp = client.get("/api/tickets/my")
    assert get_resp.status_code == 200


@pytest.mark.django_db
def test_non_operator_close_403(matrix_db: dict[str, Any]) -> None:
    retest: VulnTicket = matrix_db["own_retest"]
    for username in ("mx_owner_a", "mx_leader", "mx_auditor"):
        client: APIClient = _auth(username)
        resp = client.post(f"/api/ops/{retest.pk}/close", {"note": "关单"}, format="json")
        assert resp.status_code == 403, username
    retest.refresh_from_db()
    assert retest.state == TicketState.PENDING_RETEST


@pytest.mark.django_db
def test_illegal_submit_422_no_state_change(matrix_db: dict[str, Any]) -> None:
    illegal: VulnTicket = _make_ticket("10.20.0.1", TicketState.PENDING_ASSIGN)
    client: APIClient = _auth("mx_owner_a")
    resp = client.post(f"/api/tickets/{illegal.pk}/submit", {"evidence": {"note": "修了"}}, format="json")
    assert resp.status_code == 422
    illegal.refresh_from_db()
    assert illegal.state == TicketState.PENDING_ASSIGN


@pytest.mark.django_db
def test_owner_submit_happy_path(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    own: VulnTicket = matrix_db["own_fix"]
    resp = client.post(f"/api/tickets/{own.pk}/submit", {"evidence": {"note": "已修复"}}, format="json")
    assert resp.status_code == 200
    assert resp.data["state"] == TicketState.PENDING_RETEST
    own.refresh_from_db()
    assert own.state == TicketState.PENDING_RETEST


@pytest.mark.django_db
def test_owner_resume_delayed_to_fix(matrix_db: dict[str, Any]) -> None:
    delayed: VulnTicket = _make_ticket("10.20.0.1", TicketState.DELAYED)
    client: APIClient = _auth("mx_owner_a")
    resp = client.post(f"/api/tickets/{delayed.pk}/resume", {}, format="json")
    assert resp.status_code == 200
    assert resp.data["state"] == TicketState.PENDING_FIX


@pytest.mark.django_db
def test_owner_delay_needs_approval_403(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    own: VulnTicket = matrix_db["own_fix"]
    resp = client.post(f"/api/tickets/{own.pk}/delay", {"delay_days": 5, "reason": "等窗口"}, format="json")
    assert resp.status_code == 403


@pytest.mark.django_db
def test_leader_short_delay_ok(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_leader")
    other: VulnTicket = matrix_db["other"]
    resp = client.post(f"/api/tickets/{other.pk}/delay", {"delay_days": 10, "reason": "等窗口"}, format="json")
    assert resp.status_code == 200
    assert resp.data["state"] == TicketState.DELAYED


@pytest.mark.django_db
def test_operator_close_reject_ignore(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_operator")
    retest: VulnTicket = matrix_db["own_retest"]
    close_resp = client.post(f"/api/ops/{retest.pk}/close", {"note": "复测通过"}, format="json")
    assert close_resp.status_code == 200
    assert close_resp.data["state"] == TicketState.CLOSED

    back: VulnTicket = _make_ticket("10.20.0.1", TicketState.PENDING_RETEST)
    reject_resp = client.post(f"/api/ops/{back.pk}/reject", {"note": "仍存在"}, format="json")
    assert reject_resp.status_code == 200
    assert reject_resp.data["state"] == TicketState.PENDING_FIX

    fix: VulnTicket = matrix_db["own_fix"]
    ignore_resp = client.post(f"/api/ops/{fix.pk}/ignore", {"reason": "误报"}, format="json")
    assert ignore_resp.status_code == 200
    assert ignore_resp.data["state"] == TicketState.IGNORED

    no_reason: VulnTicket = _make_ticket("10.20.0.1", TicketState.PENDING_FIX)
    bad_resp = client.post(f"/api/ops/{no_reason.pk}/ignore", {}, format="json")
    assert bad_resp.status_code == 422


@pytest.mark.django_db
def test_bad_severity_filter_400_with_allowed_list(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    resp = client.get("/api/tickets/my", {"severity": "critical"})
    assert resp.status_code == 400
    assert "allowed" in resp.data


@pytest.mark.django_db
def test_my_filters_state_and_q(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_owner_a")
    resp = client.get("/api/tickets/my", {"state": TicketState.PENDING_FIX})
    assert resp.status_code == 200
    assert resp.data["count"] == 1
    resp_q = client.get("/api/tickets/my", {"q": "10.20.0.2"})
    assert resp_q.status_code == 200
    assert resp_q.data["count"] == 0


@pytest.mark.django_db
def test_page_size_capped_at_100(matrix_db: dict[str, Any]) -> None:
    client: APIClient = _auth("mx_operator")
    resp = client.get("/api/tickets/my", {"page_size": 1000})
    assert resp.status_code == 200
    assert len(resp.data["results"]) <= 100


@pytest.mark.django_db
def test_dashboard_numbers_reconcile(matrix_db: dict[str, Any]) -> None:
    overdue: VulnTicket = _make_ticket(
        "10.20.0.1", TicketState.PENDING_FIX,
        sla_due_at=timezone.now() - timezone.timedelta(days=1),
    )
    assert overdue.pk is not None
    client: APIClient = _auth("mx_owner_a")
    dash = client.get("/api/dashboard")
    assert dash.status_code == 200
    body = dash.data
    assert set(body) >= {"total", "by_state", "by_severity", "sla"}
    mine = client.get("/api/tickets/my", {"page_size": 100})
    assert body["total"] == mine.data["count"]
    assert sum(body["by_state"].values()) == body["total"]
    assert sum(body["by_severity"].values()) == body["total"]
    sla = body["sla"]
    assert sla["overdue"] + sla["at_risk"] + sla["ok"] + sla["no_due"] == body["total"]
    assert sla["overdue"] >= 1
    assert body["by_state"][TicketState.PENDING_FIX] >= 1


@pytest.mark.django_db
def test_audit_filters_and_owner_forbidden(matrix_db: dict[str, Any]) -> None:
    ticket: VulnTicket = matrix_db["own_fix"]
    AuditLog.objects.create(
        actor=matrix_db["operator"], action="ticket.note",
        ticket=ticket, entity="vuln_ticket", entity_id=str(ticket.pk),
        diff_json={"note": "ops-note"},
    )
    op_client: APIClient = _auth("mx_operator")
    resp = op_client.get("/api/audit", {"ticket_id": str(ticket.pk)})
    assert resp.status_code == 200
    assert resp.data["count"] >= 1
    assert all(str(row["ticket_id"]) == str(ticket.pk) for row in resp.data["results"])
    resp_actor = op_client.get("/api/audit", {"actor": "mx_operator"})
    assert resp_actor.status_code == 200
    assert resp_actor.data["count"] >= 1
    aud_client: APIClient = _auth("mx_auditor")
    assert aud_client.get("/api/audit").status_code == 200
    owner_client: APIClient = _auth("mx_owner_a")
    assert owner_client.get("/api/audit").status_code == 403


@pytest.mark.django_db
def test_unauthenticated_401(matrix_db: dict[str, Any]) -> None:
    client = APIClient()
    assert client.get("/api/tickets/my").status_code in (401, 403)
    assert client.get("/api/dashboard").status_code in (401, 403)


PNG_1PX: bytes = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)


@pytest.mark.django_db
def test_attachment_upload_matrix(matrix_db: dict[str, Any]) -> None:
    from django.core.files.uploadedfile import SimpleUploadedFile

    ticket: VulnTicket = matrix_db["own_fix"]
    owner_client: APIClient = _auth("mx_owner_a")
    png = SimpleUploadedFile("proof.png", PNG_1PX, content_type="image/png")
    resp = owner_client.post(
        f"/api/tickets/{ticket.pk}/attachments", {"file": png}, format="multipart"
    )
    assert resp.status_code == 201, resp.content
    assert resp.data["url"].endswith(".png")
    detail = owner_client.get(f"/api/tickets/{ticket.pk}")
    assert detail.status_code == 200
    assert len(detail.data["attachments"]) == 1

    other_client: APIClient = _auth("mx_owner_b")
    png2 = SimpleUploadedFile("proof.png", PNG_1PX, content_type="image/png")
    assert other_client.post(
        f"/api/tickets/{ticket.pk}/attachments", {"file": png2}, format="multipart"
    ).status_code == 404

    txt = SimpleUploadedFile("note.txt", b"hello", content_type="text/plain")
    assert owner_client.post(
        f"/api/tickets/{ticket.pk}/attachments", {"file": txt}, format="multipart"
    ).status_code == 400

    big = SimpleUploadedFile(
        "big.png", b"\x89PNG" + b"\x00" * (6 * 1024 * 1024), content_type="image/png"
    )
    assert owner_client.post(
        f"/api/tickets/{ticket.pk}/attachments", {"file": big}, format="multipart"
    ).status_code == 400

    aud_client: APIClient = _auth("mx_auditor")
    png3 = SimpleUploadedFile("proof.png", PNG_1PX, content_type="image/png")
    assert aud_client.post(
        f"/api/tickets/{ticket.pk}/attachments", {"file": png3}, format="multipart"
    ).status_code == 403


@pytest.mark.django_db
def test_ops_assign_and_users(matrix_db: dict[str, Any]) -> None:
    pending = _make_ticket("10.20.0.9", state=TicketState.PENDING_ASSIGN)
    op_client: APIClient = _auth("mx_operator")

    users = op_client.get("/api/ops/users")
    assert users.status_code == 200
    names = [row["username"] for row in users.data["results"]]
    assert "mx_owner_a" in names and "mx_auditor" not in names

    resp = op_client.post(
        f"/api/ops/{pending.pk}/assign", {"assignee": "mx_owner_a"}, format="json"
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["state"] == TicketState.PENDING_FIX
    assert resp.data["assignee"] == "mx_owner_a"

    resp = op_client.post(
        f"/api/ops/{pending.pk}/assign", {"assignee": "mx_owner_b"}, format="json"
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["assignee"] == "mx_owner_b"
    assert resp.data["state"] == TicketState.PENDING_FIX

    assert op_client.post(
        f"/api/ops/{pending.pk}/assign", {"assignee": "ghost"}, format="json"
    ).status_code == 404
    assert op_client.post(
        f"/api/ops/{pending.pk}/assign", {"assignee": "mx_auditor"}, format="json"
    ).status_code == 422

    owner_client: APIClient = _auth("mx_owner_a")
    assert owner_client.post(
        f"/api/ops/{pending.pk}/assign", {"assignee": "mx_owner_a"}, format="json"
    ).status_code == 403
    assert owner_client.get("/api/ops/users").status_code == 403


@pytest.mark.django_db
def test_delay_request_approval_flow(matrix_db: dict[str, Any]) -> None:
    ticket: VulnTicket = _make_ticket("10.20.0.3", state=TicketState.PENDING_FIX)
    Asset.objects.create(ip="10.20.0.3")
    AssetOwnerMap.objects.create(
        ip_id="10.20.0.3", user=matrix_db["owner_a"], valid_from=timezone.now()
    )
    owner_client: APIClient = _auth("mx_owner_a")
    resp = owner_client.post(
        f"/api/tickets/{ticket.pk}/delay-request",
        {"delay_days": 7, "reason": "等补丁窗口"},
        format="json",
    )
    assert resp.status_code == 201, resp.content
    req_id = resp.data["id"]
    assert resp.data["status"] == "待审批"

    dup = owner_client.post(
        f"/api/tickets/{ticket.pk}/delay-request",
        {"delay_days": 7, "reason": "再申请"},
        format="json",
    )
    assert dup.status_code == 422

    leader_client: APIClient = _auth("mx_leader")
    pend = leader_client.get("/api/ops/delay-requests", {"status": "待审批"})
    assert pend.status_code == 200
    assert any(str(row["id"]) == str(req_id) for row in pend.data["results"])

    ok = leader_client.post(
        f"/api/ops/delay-requests/{req_id}/approve", {}, format="json"
    )
    assert ok.status_code == 200, ok.content
    assert ok.data["status"] == "已批准"
    ticket.refresh_from_db()
    assert ticket.state == TicketState.DELAYED

    again = leader_client.post(
        f"/api/ops/delay-requests/{req_id}/approve", {}, format="json"
    )
    assert again.status_code == 422


@pytest.mark.django_db
def test_delay_request_reject_and_leader_30d_cap(matrix_db: dict[str, Any]) -> None:
    ticket: VulnTicket = _make_ticket("10.20.0.4", state=TicketState.PENDING_FIX)
    Asset.objects.create(ip="10.20.0.4")
    AssetOwnerMap.objects.create(
        ip_id="10.20.0.4", user=matrix_db["owner_b"], valid_from=timezone.now()
    )
    owner_client: APIClient = _auth("mx_owner_b")
    resp = owner_client.post(
        f"/api/tickets/{ticket.pk}/delay-request",
        {"delay_days": 60, "reason": "大版本重构"},
        format="json",
    )
    assert resp.status_code == 201, resp.content

    leader_client: APIClient = _auth("mx_leader")
    denied = leader_client.post(
        f"/api/ops/delay-requests/{resp.data['id']}/approve", {}, format="json"
    )
    assert denied.status_code == 403

    no = leader_client.post(
        f"/api/ops/delay-requests/{resp.data['id']}/reject",
        {"note": "先打补丁"},
        format="json",
    )
    assert no.status_code == 200, no.content
    assert no.data["status"] == "已驳回"
    ticket.refresh_from_db()
    assert ticket.state == TicketState.PENDING_FIX


@pytest.mark.django_db
def test_user_admin_crud(matrix_db: dict[str, Any]) -> None:
    del matrix_db
    op_client: APIClient = _auth("mx_operator")

    created = op_client.post(
        "/api/ops/admin/users",
        {"username": "newbie", "dept": "研发部", "email": "newbie@example.com",
         "role": "owner", "wecom_userid": "newbie"},
        format="json",
    )
    assert created.status_code == 201, created.content
    assert created.data["temp_password"]

    dup = op_client.post("/api/ops/admin/users", {"username": "newbie"}, format="json")
    assert dup.status_code == 400

    listed = op_client.get("/api/ops/admin/users", {"q": "newb"})
    assert listed.status_code == 200
    assert listed.data["count"] == 1

    patched = op_client.patch(
        "/api/ops/admin/users/newbie", {"dept": "安全部", "is_active": False},
        format="json",
    )
    assert patched.status_code == 200, patched.content
    assert patched.data["dept"] == "安全部"
    assert patched.data["is_active"] is False

    reset = op_client.post("/api/ops/admin/users/newbie", {}, format="json")
    assert reset.status_code == 200
    assert reset.data["temp_password"]

    owner_client: APIClient = _auth("mx_owner_a")
    assert owner_client.get("/api/ops/admin/users").status_code == 403
    assert owner_client.post(
        "/api/ops/admin/users", {"username": "hacker"}, format="json"
    ).status_code == 403


@pytest.mark.django_db
def test_user_admin_delete(matrix_db: dict[str, Any]) -> None:
    """删用户：在办工单退回(assignee SET_NULL)+审计留痕+守卫(自删400/删管理员403/404)."""
    from apps.audit.models import AuditLog

    victim: User = _make_user("mx_del_user", Role.OWNER)
    open_t: VulnTicket = _make_ticket("10.20.0.77", TicketState.PENDING_FIX, assignee=victim)
    closed_t: VulnTicket = _make_ticket("10.20.0.78", TicketState.CLOSED, assignee=victim)
    client: APIClient = _auth("mx_operator")

    resp = client.delete("/api/ops/admin/users/mx_del_user")
    assert resp.status_code == 200, resp.content
    assert resp.data["deleted"] is True
    assert resp.data["username"] == "mx_del_user"
    assert resp.data["unassigned_open_tickets"] == 1
    assert not User.objects.filter(username="mx_del_user").exists()
    open_t.refresh_from_db()
    assert open_t.assignee is None
    closed_t.refresh_from_db()
    assert closed_t.assignee is None
    row = AuditLog.objects.filter(action="user.delete", entity_id="mx_del_user").first()
    assert row is not None
    assert row.diff_json["unassigned_open_tickets"] == 1
    assert client.delete("/api/ops/admin/users/mx_del_user").status_code == 404
    assert client.delete("/api/ops/admin/users/mx_operator").status_code == 400
    _make_user("mx_admin_victim", Role.ADMIN)
    assert client.delete("/api/ops/admin/users/mx_admin_victim").status_code == 403
    admin_client: APIClient = _auth("mx_admin")
    assert admin_client.delete("/api/ops/admin/users/mx_admin_victim").status_code == 200


@pytest.mark.django_db
def test_manual_assign_drops_ticket_from_orphan_and_unassigned(matrix_db: dict[str, Any]) -> None:
    """无主列只收 assignee NULL：手工派单后工单同时退出无主/未分配两列."""
    lonely: VulnTicket = _make_ticket("10.20.0.9", TicketState.PENDING_ASSIGN)
    client: APIClient = _auth("mx_operator")
    orphan_before = client.get("/api/ops/pool", {"orphan": "true"})
    assert orphan_before.status_code == 200
    assert lonely.pk in {row["id"] for row in orphan_before.data["results"]}
    unassigned_before = client.get("/api/ops/pool", {"unassigned": "true"})
    assert lonely.pk in {row["id"] for row in unassigned_before.data["results"]}
    assign = client.post(
        f"/api/ops/{lonely.pk}/assign", {"assignee": "mx_owner_a"}, format="json"
    )
    assert assign.status_code == 200, assign.content
    orphan_after = client.get("/api/ops/pool", {"orphan": "true"})
    assert lonely.pk not in {row["id"] for row in orphan_after.data["results"]}
    unassigned_after = client.get("/api/ops/pool", {"unassigned": "true"})
    assert lonely.pk not in {row["id"] for row in unassigned_after.data["results"]}


@pytest.mark.django_db
def test_pool_row_carries_first_seen_and_source(matrix_db: dict[str, Any]) -> None:
    """列表行带发现日期 + 批次来源标签；无批次时 source 为 None."""
    batch = ScanBatch.objects.create(
        file_name="rsas-2026-09-01.zip",
        file_hash=uuid.uuid4().hex,
        source=BatchSource.MANUAL,
    )
    seen = timezone.now() - timezone.timedelta(days=9)
    tagged: VulnTicket = _make_ticket(
        "10.20.0.1", TicketState.PENDING_FIX, batch=batch, first_seen_at=seen
    )
    client: APIClient = _auth("mx_operator")
    resp = client.get("/api/ops/pool")
    assert resp.status_code == 200
    rows = {row["id"]: row for row in resp.data["results"]}
    assert rows[tagged.pk]["source"] == "rsas-2026-09-01.zip"
    assert str(rows[tagged.pk]["first_seen_at"]).startswith(seen.date().isoformat())
    plain = rows[matrix_db["own_fix"].pk]
    assert plain["source"] is None


@pytest.mark.django_db
def test_manual_create_custom_source(matrix_db: dict[str, Any]) -> None:
    """手工建单手填来源：同名复用同一批次；超长 400."""
    from apps.imports.models import ScanBatch

    client: APIClient = _auth("mx_operator")
    first = client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.9", "severity": "高", "title": "HW 发现弱口令",
         "source": "HW2026行动"},
        format="json",
    )
    assert first.status_code == 201, first.content
    assert first.data["source"] == "HW2026行动"
    second = client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.9", "severity": "中", "title": "HW 发现越权"},
        format="json",
    )
    assert second.status_code == 201, second.content
    assert second.data["source"] == "手工录入"
    client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.9", "severity": "高", "title": "HW 复测",
         "source": "HW2026行动"},
        format="json",
    )
    assert ScanBatch.objects.filter(file_name="HW2026行动").count() == 1
    assert ScanBatch.objects.filter(file_name="手工录入").count() == 1
    too_long = client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.9", "severity": "高", "title": "x",
         "source": "超" * 65},
        format="json",
    )
    assert too_long.status_code == 400


@pytest.mark.django_db
def test_pool_filters_severity_and_q(matrix_db: dict[str, Any]) -> None:
    """工单池支持 severity + q（IP/插件/CVE/负责人）组合过滤；非法严重性 400."""
    _make_ticket("10.20.0.9", TicketState.PENDING_ASSIGN, severity=Severity.LOW,
                 plugin_name="本地测试插件", cve="CVE-2026-0101")
    _make_ticket("10.20.1.1", TicketState.PENDING_FIX, assignee=matrix_db["owner_a"])
    _make_ticket("10.20.1.2", TicketState.PENDING_FIX, assignee=matrix_db["owner_b"])
    client: APIClient = _auth("mx_operator")
    sev = client.get("/api/ops/pool", {"severity": "低"})
    assert sev.status_code == 200
    assert {row["ip"] for row in sev.data["results"]} == {"10.20.0.9"}
    q_ip = client.get("/api/ops/pool", {"q": "10.20.0.9"})
    assert q_ip.status_code == 200
    assert q_ip.data["count"] == 1
    q_cve = client.get("/api/ops/pool", {"q": "cve-2026-0101"})
    assert q_cve.data["count"] == 1
    q_owner = client.get("/api/ops/pool", {"q": "mx_owner_a"})
    assert q_owner.status_code == 200
    assert {row["ip"] for row in q_owner.data["results"]} == {"10.20.1.1"}
    q_owner_partial = client.get("/api/ops/pool", {"q": "owner_b"})
    assert {row["ip"] for row in q_owner_partial.data["results"]} == {"10.20.1.2"}
    q_owner_wide = client.get("/api/ops/pool", {"q": "mx_owner"})
    assert {row["ip"] for row in q_owner_wide.data["results"]} == {"10.20.1.1", "10.20.1.2"}
    q_combo = client.get("/api/ops/pool", {"severity": "高", "q": "10.20.0"})
    assert q_combo.status_code == 200
    assert {row["ip"] for row in q_combo.data["results"]} == {"10.20.0.1", "10.20.0.2"}
    bad = client.get("/api/ops/pool", {"severity": "极高"})
    assert bad.status_code == 400
    assert "allowed" in bad.data
    multi = client.get("/api/ops/pool", {"severity": "高,低"})
    assert multi.status_code == 200
    got_ips = sorted(row["ip"] for row in multi.data["results"])
    assert got_ips == [
        "10.20.0.1", "10.20.0.1", "10.20.0.2", "10.20.0.9", "10.20.1.1", "10.20.1.2",
    ]
    multi_bad = client.get("/api/ops/pool", {"severity": "高,极高"})
    assert multi_bad.status_code == 400


@pytest.mark.django_db
def test_ops_departments_tree(matrix_db: dict[str, Any]) -> None:
    """部门树：首个 - 或 / 前为一级、树值为完整原串；owner 403，未登录 401."""
    _make_user("mx_owner_c", Role.OWNER, dept="biza/一组")
    _make_user("mx_owner_d", Role.OWNER, dept="biza/二组")
    _make_user("mx_owner_e", Role.OWNER, dept="  biza/一组  ")
    _make_user(
        "mx_owner_f", Role.OWNER, dept="平台与医技-数据平台中心-数据应用研发部-数据创新研发部"
    )
    client: APIClient = _auth("mx_operator")
    resp = client.get("/api/ops/departments")
    assert resp.status_code == 200
    assert resp.data["first"] == ["audit", "biza", "bizb", "sec", "平台与医技"]
    assert resp.data["tree"]["biza"] == ["biza", "biza/一组", "biza/二组"]
    assert resp.data["tree"]["平台与医技"] == [
        "平台与医技-数据平台中心-数据应用研发部-数据创新研发部"
    ]
    assert resp.data["tree"]["sec"] == ["sec"]
    assert resp.data["count"] == 5
    owner_client: APIClient = _auth("mx_owner_a")
    assert owner_client.get("/api/ops/departments").status_code == 403
    assert APIClient().get("/api/ops/departments").status_code in (401, 403)


@pytest.mark.django_db
def test_pool_dept_filters() -> None:
    """pool ?dept= 精确匹配完整原串、?dept_prefix= 前缀匹配一级部门."""
    owner_a: User = _make_user(
        "pd_owner_a", Role.OWNER, dept="平台与医技-数据平台中心-数据应用研发部"
    )
    owner_b: User = _make_user(
        "pd_owner_b", Role.OWNER, dept="平台与医技-数据平台中心-数据应用研发部-数据创新研发部"
    )
    _make_user("pd_operator", Role.OPERATOR)
    t_a: VulnTicket = _make_ticket("10.94.0.1", TicketState.PENDING_FIX, assignee=owner_a)
    t_b: VulnTicket = _make_ticket("10.94.0.2", TicketState.PENDING_FIX, assignee=owner_b)
    _make_ticket("10.94.0.3", TicketState.PENDING_FIX)
    client: APIClient = _auth("pd_operator")
    prefix = client.get("/api/ops/pool", {"dept_prefix": "平台与医技"})
    assert prefix.status_code == 200
    assert {r["id"] for r in prefix.data["results"]} == {t_a.pk, t_b.pk}
    deep = client.get("/api/ops/pool", {"dept_prefix": "平台与医技-数据平台中心"})
    assert deep.data["count"] == 2
    exact = client.get("/api/ops/pool", {"dept": "平台与医技-数据平台中心-数据应用研发部"})
    assert {r["id"] for r in exact.data["results"]} == {t_a.pk}
    none = client.get("/api/ops/pool", {"dept": "不存在的部门"})
    assert none.data["count"] == 0


@pytest.mark.django_db
def test_manual_create_auto_dispatches_via_owner_map(matrix_db: dict[str, Any]) -> None:
    """手工建单：有映射IP自动派单→待修复；无映射→待分配进无主池."""
    client: APIClient = _auth("mx_operator")
    auto = client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.1", "port": 8080, "severity": "高",
         "title": "第三方渗透测试发现弱口令", "cve": "CVE-2026-0001"},
        format="json",
    )
    assert auto.status_code == 201, auto.content
    assert auto.data["assignee"] == "mx_owner_a"
    assert auto.data["state"] == TicketState.PENDING_FIX
    assert auto.data["source"] == "手工录入"
    assert auto.data["sla_due_at"] is None  # SLA 未提醒不计时，首次提醒起算
    assert auto.data["first_seen_at"]
    orphan = client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.9", "severity": "中", "title": "威胁情报外泄数据核查"},
        format="json",
    )
    assert orphan.status_code == 201, orphan.content
    assert orphan.data["assignee"] is None
    assert orphan.data["state"] == TicketState.PENDING_ASSIGN
    assert orphan.data["sla_due_at"] is None  # 同上
    explicit = client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.9", "severity": "低", "title": "手工巡检",
         "assignee": "mx_owner_b"},
        format="json",
    )
    assert explicit.status_code == 201, explicit.content
    assert explicit.data["assignee"] == "mx_owner_b"
    assert explicit.data["state"] == TicketState.PENDING_FIX


@pytest.mark.django_db
def test_manual_create_validation(matrix_db: dict[str, Any]) -> None:
    """手工建单：非法IP/严重性/缺标题 400；owner 建单 403；审计员接单 422."""
    client: APIClient = _auth("mx_operator")
    assert client.post(
        "/api/ops/tickets", {"ip": "999.1.1.1", "severity": "高", "title": "x"},
        format="json",
    ).status_code == 400
    bad_sev = client.post(
        "/api/ops/tickets", {"ip": "10.20.0.9", "severity": "极高", "title": "x"},
        format="json",
    )
    assert bad_sev.status_code == 400
    assert "allowed" in bad_sev.data
    assert client.post(
        "/api/ops/tickets", {"ip": "10.20.0.9", "severity": "低"},
        format="json",
    ).status_code == 400
    assert client.post(
        "/api/ops/tickets",
        {"ip": "10.20.0.9", "severity": "低", "title": "x", "assignee": "mx_auditor"},
        format="json",
    ).status_code == 422
    owner_client: APIClient = _auth("mx_owner_a")
    assert owner_client.post(
        "/api/ops/tickets", {"ip": "10.20.0.9", "severity": "低", "title": "x"},
        format="json",
    ).status_code == 403


@pytest.mark.django_db
def test_operator_reset_admin_password_403(matrix_db: dict[str, Any]) -> None:
    del matrix_db
    client: APIClient = _auth("mx_operator")
    resp = client.post("/api/ops/admin/users/mx_admin", {}, format="json")
    assert resp.status_code == 403
    assert resp.data["detail"] == "仅管理员可重置管理员密码"


@pytest.mark.django_db
def test_operator_deactivate_admin_403(matrix_db: dict[str, Any]) -> None:
    del matrix_db
    client: APIClient = _auth("mx_operator")
    resp = client.patch(
        "/api/ops/admin/users/mx_admin", {"is_active": False}, format="json"
    )
    assert resp.status_code == 403
    assert resp.data["detail"] == "仅管理员可停用管理员账号"
    assert User.objects.get(username="mx_admin").is_active is True


@pytest.mark.django_db
def test_admin_resets_operator_200(matrix_db: dict[str, Any]) -> None:
    del matrix_db
    client: APIClient = _auth("mx_admin")
    resp = client.post("/api/ops/admin/users/mx_operator", {}, format="json")
    assert resp.status_code == 200
    assert resp.data["reset"] is True


@pytest.mark.django_db
def test_operator_resets_operator_200(matrix_db: dict[str, Any]) -> None:
    _make_user("mx_operator2", Role.OPERATOR, dept="sec")
    client: APIClient = _auth("mx_operator")
    resp = client.post("/api/ops/admin/users/mx_operator2", {}, format="json")
    assert resp.status_code == 200
    assert resp.data["reset"] is True


@pytest.mark.django_db
def test_cmdb_sync_unauthenticated_denied(matrix_db: dict[str, Any]) -> None:
    del matrix_db
    assert APIClient().post("/api/cmdb/sync").status_code in (401, 403)


@pytest.mark.django_db
def test_cmdb_sync_operator_reaches_client(matrix_db: dict[str, Any]) -> None:
    from unittest import mock

    del matrix_db
    client: APIClient = _auth("mx_operator")
    summary = {"upserted": 2, "remapped": 1, "orphaned": 0}
    with mock.patch("apps.cmdb.views.sync_cmdb") as task:
        task.run.return_value = summary
        resp = client.post("/api/cmdb/sync")
    assert resp.status_code == 200
    assert resp.data == summary


@pytest.mark.django_db
def test_orphans_unauthenticated_denied(matrix_db: dict[str, Any]) -> None:
    del matrix_db
    assert APIClient().get("/api/assets/orphans").status_code in (401, 403)


@pytest.mark.django_db
def test_sniff_rejects_fake_png(matrix_db: dict[str, Any]) -> None:
    from django.core.files.uploadedfile import SimpleUploadedFile

    ticket: VulnTicket = matrix_db["own_fix"]
    client: APIClient = _auth("mx_owner_a")
    fake = SimpleUploadedFile("fake.png", b"AAAA" * 64, content_type="image/png")
    resp = client.post(
        f"/api/tickets/{ticket.pk}/attachments", {"file": fake}, format="multipart"
    )
    assert resp.status_code == 400
    assert resp.data["detail"] == "文件头与图片格式不符"


@pytest.mark.django_db
def test_sniff_accepts_minimal_png(matrix_db: dict[str, Any]) -> None:
    from django.core.files.uploadedfile import SimpleUploadedFile

    ticket: VulnTicket = matrix_db["own_fix"]
    client: APIClient = _auth("mx_owner_a")
    minimal = SimpleUploadedFile(
        "mini.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, content_type="image/png"
    )
    resp = client.post(
        f"/api/tickets/{ticket.pk}/attachments", {"file": minimal}, format="multipart"
    )
    assert resp.status_code == 201, resp.content
    assert resp.data["name"] == "mini.png"


@pytest.mark.django_db
def test_detail_query_count_bounded(matrix_db: dict[str, Any]) -> None:
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    ticket: VulnTicket = matrix_db["own_fix"]
    client: APIClient = _auth("mx_owner_a")
    with CaptureQueriesContext(connection) as ctx:
        resp = client.get(f"/api/tickets/{ticket.pk}")
    assert resp.status_code == 200
    assert len(ctx) <= 5


@pytest.mark.django_db
def test_new_indexes_present(matrix_db: dict[str, Any]) -> None:
    from apps.accounts.models import User as AuthUser
    from apps.assets.models import AssetOwnerMap

    del matrix_db

    def _field_sets(model: object) -> list[set[str]]:
        return [set(idx.fields) for idx in model._meta.indexes]  # type: ignore[attr-defined]

    ticket_sets = _field_sets(VulnTicket)
    assert {"severity"} in ticket_sets
    assert {"state", "severity"} in ticket_sets
    assert {"-updated_at"} in ticket_sets
    assert {"valid_to"} in _field_sets(AssetOwnerMap)
    assert {"dept"} in _field_sets(AuthUser)


@pytest.mark.django_db
def test_ops_edit_ticket_content(matrix_db: dict[str, Any]) -> None:
    """改单：内容字段可改+SLA重算+审计行；IP/端口拒绝；闭合单422."""
    from apps.audit.models import AuditLog

    target: VulnTicket = matrix_db["own_fix"]
    client: APIClient = _auth("mx_operator")
    old_due = target.sla_due_at
    resp = client.patch(
        f"/api/ops/{target.pk}/edit",
        {"title": "运营修正标题", "severity": "严重",
         "description": "补充说明", "cve": "CVE-2026-1234"},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert resp.data["title"] == "运营修正标题"
    assert resp.data["severity"] == "严重"
    assert resp.data["sla_due_at"] != (old_due.isoformat() if old_due else None)
    target.refresh_from_db()
    assert target.plugin_name == "运营修正标题"
    assert target.description == "补充说明"
    row = AuditLog.objects.filter(
        action="ticket.update", entity_id=str(target.pk)
    ).order_by("-id").first()
    assert row is not None
    assert set(row.diff_json["changed"]) >= {"plugin_name", "severity", "sla_due_at"}
    assert client.patch(
        f"/api/ops/{target.pk}/edit", {"ip": "1.2.3.4"}, format="json"
    ).status_code == 400
    assert client.patch(
        f"/api/ops/{target.pk}/edit", {"severity": "极高"}, format="json"
    ).status_code == 400
    assert client.patch(
        f"/api/ops/{target.pk}/edit", {}, format="json"
    ).status_code == 400
    closed: VulnTicket = _make_ticket("10.20.0.9", TicketState.CLOSED)
    assert client.patch(
        f"/api/ops/{closed.pk}/edit", {"title": "x"}, format="json"
    ).status_code == 422
    owner_client: APIClient = _auth("mx_owner_a")
    assert owner_client.patch(
        f"/api/ops/{target.pk}/edit", {"title": "hack"}, format="json"
    ).status_code == 403


@pytest.mark.django_db
def test_ops_edit_ticket_source(matrix_db: dict[str, Any]) -> None:
    """改单换来源：切同名手工批次（复用）、审计记旧新、超长400、空串保持."""
    from apps.audit.models import AuditLog
    from apps.imports.models import ScanBatch

    target: VulnTicket = matrix_db["own_fix"]
    client: APIClient = _auth("mx_operator")
    first = client.patch(
        f"/api/ops/{target.pk}/edit", {"source": "HW2026复测"}, format="json"
    )
    assert first.status_code == 200, first.content
    assert first.data["source"] == "HW2026复测"
    target.refresh_from_db()
    assert target.batch is not None
    assert target.batch.file_name == "HW2026复测"
    row = AuditLog.objects.filter(
        action="ticket.update", entity_id=str(target.pk)
    ).order_by("-id").first()
    assert row is not None
    assert row.diff_json["changed"]["source"] == {"old": None, "new": "HW2026复测"}
    again = client.patch(
        f"/api/ops/{target.pk}/edit", {"source": "HW2026复测"}, format="json"
    )
    assert again.status_code == 400  # 无变化
    assert ScanBatch.objects.filter(file_name="HW2026复测").count() == 1
    keep = client.patch(
        f"/api/ops/{target.pk}/edit", {"source": "", "title": " keep-batch"}, format="json"
    )
    assert keep.status_code == 200
    assert keep.data["source"] == "HW2026复测"
    too_long = client.patch(
        f"/api/ops/{target.pk}/edit", {"source": "源" * 65}, format="json"
    )
    assert too_long.status_code == 400


@pytest.mark.django_db
def test_ops_delete_ticket(matrix_db: dict[str, Any]) -> None:
    """删单：任意状态硬删+审计行存留(SET_NULL)+404；owner 403."""
    from apps.audit.models import AuditLog

    target: VulnTicket = matrix_db["own_fix"]
    client: APIClient = _auth("mx_operator")
    resp = client.delete(f"/api/ops/{target.pk}")
    assert resp.status_code == 200, resp.content
    assert resp.data["deleted"] is True
    assert resp.data["id"] == target.pk
    assert resp.data["ip"] == target.ip
    assert not VulnTicket.objects.filter(pk=target.pk).exists()
    row = AuditLog.objects.filter(action="ticket.delete", entity_id=str(target.pk)).first()
    assert row is not None
    assert row.ticket_id is None
    assert row.diff_json["deleted"]["ip"] == target.ip
    assert client.delete(f"/api/ops/{target.pk}").status_code == 404
    closed: VulnTicket = _make_ticket("10.20.0.99", TicketState.CLOSED)
    assert client.delete(f"/api/ops/{closed.pk}").status_code == 200
    owner_client: APIClient = _auth("mx_owner_a")
    fresh: VulnTicket = _make_ticket("10.20.0.98")
    assert owner_client.delete(f"/api/ops/{fresh.pk}").status_code == 403
    assert VulnTicket.objects.filter(pk=fresh.pk).exists()
