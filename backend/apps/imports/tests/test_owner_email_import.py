"""负责人邮箱表导入: POST /api/imports/owner-emails (update existing users only)."""

from __future__ import annotations

from typing import Any

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.audit.models import AuditLog

PW: str = "pw-email-test-123"

EMAIL_OK: str = (
    "负责人,邮箱\n"
    "张三(111),zhangsan@corp.com\n"
    "李四,lisi@corp.com\n"
)


def _auth_op() -> APIClient:
    User.objects.create_user(
        username="email_op", password=PW, wecom_userid="email_op", role=Role.OPERATOR
    )
    client = APIClient()
    login = client.post(
        "/api/auth/local", {"username": "email_op", "password": PW}, format="json"
    )
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


def _upload(client: APIClient, text: str, dry_run: bool) -> Any:
    f = SimpleUploadedFile("emails.csv", text.encode("utf-8"), content_type="text/csv")
    suffix = "?dry_run=true" if dry_run else ""
    return client.post(f"/api/imports/owner-emails{suffix}", {"file": f}, format="multipart")


@pytest.mark.django_db
def test_owner_email_import_updates_and_audits() -> None:
    User.objects.create_user(
        username="张三", password=PW, wecom_userid="111", role=Role.OWNER, email="old@corp.com"
    )
    User.objects.create_user(username="李四", password=PW, role=Role.OWNER)
    client = _auth_op()

    dry = _upload(client, EMAIL_OK, dry_run=True)
    assert dry.status_code == 200, dry.content
    assert dry.data["updated_preview"] == 2
    assert User.objects.get(username="张三").email == "old@corp.com"

    resp = _upload(client, EMAIL_OK, dry_run=False)
    assert resp.status_code in (200, 201), resp.content
    assert resp.data["updated"] == 2
    assert resp.data["total_rows"] == 2
    assert User.objects.get(username="张三").email == "zhangsan@corp.com"
    assert User.objects.get(username="李四").email == "lisi@corp.com"
    rows = AuditLog.objects.filter(action="user.email.import").order_by("id")
    assert rows.count() == 2
    assert list(rows.values_list("entity_id", flat=True)) == ["张三", "李四"]
    assert rows.first().diff_json["email"] == {"old": "old@corp.com", "new": "zhangsan@corp.com"}


@pytest.mark.django_db
def test_owner_email_import_missing_user_and_gonghao_lookup() -> None:
    User.objects.create_user(
        username="王五", password=PW, wecom_userid="555", role=Role.OWNER
    )
    client = _auth_op()
    body = (
        "工号,邮箱\n"
        "555,wangwu@corp.com\n"
        "999,ghost@corp.com\n"
    )
    resp = _upload(client, body, dry_run=False)
    assert resp.status_code == 207, resp.content
    assert resp.data["updated"] == 1
    assert User.objects.get(username="王五").email == "wangwu@corp.com"
    assert resp.data["missing"] == [{"row": 3, "name": "999"}]

    resp2 = _upload(client, "负责人,邮箱\n赵六,zhaoliu@corp.com\n", dry_run=False)
    assert resp2.status_code == 207
    assert resp2.data["updated"] == 0
    assert not User.objects.filter(username="赵六").exists()


@pytest.mark.django_db
def test_owner_email_missing_columns_400() -> None:
    client = _auth_op()
    resp = _upload(client, "负责人\n张三\n", dry_run=False)
    assert resp.status_code == 400
    assert "邮箱" in str(resp.data["errors"])
