"""Integration-settings store + admin API tests.

DB-backed knobs on the /ops/config page: shape/allowlist, RBAC, secret
masking, validation, DB-wins-over-env precedence, audit rows, mocked
connectivity probes, and the field-map viewer. DB_ENGINE=sqlite, zero real
network (all HTTP/SMTP seams mocked).
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.audit.models import AuditLog
from apps.sysconfig import store as cfg
from apps.sysconfig.models import IntegrationSetting

PW: str = "pw-sysconfig-test-123"

EXPECTED_KEYS: frozenset[str] = frozenset(
    {
        "smtp.enabled", "smtp.host", "smtp.port", "smtp.user", "smtp.password",
        "smtp.use_ssl", "smtp.use_tls", "smtp.from", "smtp.subject_prefix",
        "wecom.login_corpid", "wecom.login_secret", "wecom.bot_webhook",
        "cmdb.base_url", "cmdb.token",
    }
)

SECRET_KEYS: frozenset[str] = frozenset(
    {"smtp.password", "wecom.login_secret", "wecom.bot_webhook", "cmdb.token"}
)


def _make_user(username: str, role: str, **kwargs: Any) -> User:
    params: dict[str, Any] = {"username": username, "password": PW, "wecom_userid": username, "role": role}
    params.update(kwargs)
    return User.objects.create_user(**params)


def _auth(username: str) -> APIClient:
    client = APIClient()
    login = client.post("/api/auth/local", {"username": username, "password": PW}, format="json")
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


@pytest.fixture
def accounts(db: Any) -> dict[str, APIClient]:
    _make_user("sc_admin", Role.ADMIN)
    _make_user("sc_operator", Role.OPERATOR)
    _make_user("sc_owner", Role.OWNER)
    return {"admin": _auth("sc_admin"), "operator": _auth("sc_operator"), "owner": _auth("sc_owner")}


def _fields_by_key(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for group in body["groups"]:
        assert {"id", "label", "fields"} <= set(group)
        for field in group["fields"]:
            out[field["key"]] = field
    return out


@pytest.mark.django_db
def test_admin_get_shape_and_exact_allowlist(accounts: dict[str, APIClient]) -> None:
    resp = accounts["admin"].get("/api/ops/integrations")
    assert resp.status_code == 200, resp.content
    fields = _fields_by_key(resp.data)
    assert set(fields) == set(EXPECTED_KEYS)
    for key, field in fields.items():
        assert field["label"], key
        if key in SECRET_KEYS:
            assert field["secret"] is True, key
            assert "value" not in field, key
            assert isinstance(field["configured"], bool), key
        else:
            assert field["secret"] is False, key
            assert "value" in field, key
            assert isinstance(field["configured"], bool), key
    assert isinstance(fields["smtp.enabled"]["value"], bool)
    assert isinstance(fields["smtp.port"]["value"], int)


@pytest.mark.django_db
def test_operator_forbidden_on_get_put_test(accounts: dict[str, APIClient]) -> None:
    op = accounts["operator"]
    assert op.get("/api/ops/integrations").status_code == 403
    assert op.put("/api/ops/integrations", {"key": "smtp.host", "value": "x"}, format="json").status_code == 403
    assert op.post("/api/ops/integrations/test", {"key": "smtp", "to": "a@b.c"}, format="json").status_code == 403
    assert accounts["owner"].get("/api/ops/integrations").status_code == 403


@pytest.mark.django_db
def test_secret_never_leaks_in_get_or_audit(accounts: dict[str, APIClient]) -> None:
    admin = accounts["admin"]
    put = admin.put("/api/ops/integrations", {"key": "smtp.password", "value": "s3cr3t-pw"}, format="json")
    assert put.status_code == 200, put.content
    assert put.data == {"key": "smtp.password", "configured": True}
    body = admin.get("/api/ops/integrations")
    assert body.status_code == 200
    assert "s3cr3t-pw" not in body.content.decode()
    row = AuditLog.objects.filter(action="integration.update", entity="integration_setting",
                                  entity_id="smtp.password").latest("id")
    assert row.diff_json.get("value") == "****"
    assert "s3cr3t-pw" not in str(row.diff_json)


@pytest.mark.django_db
def test_empty_secret_put_keeps_old_value(accounts: dict[str, APIClient]) -> None:
    admin = accounts["admin"]
    first = admin.put("/api/ops/integrations", {"key": "cmdb.token", "value": "tok-keep"}, format="json")
    assert first.status_code == 200
    kept = admin.put("/api/ops/integrations", {"key": "cmdb.token", "value": ""}, format="json")
    assert kept.status_code == 200
    assert kept.data == {"key": "cmdb.token", "configured": True}
    assert IntegrationSetting.objects.get(key="cmdb.token").value == "tok-keep"


@pytest.mark.django_db
def test_db_wins_then_clear_falls_back_to_env(accounts: dict[str, APIClient], monkeypatch: pytest.MonkeyPatch) -> None:
    admin = accounts["admin"]
    monkeypatch.setenv("EMAIL_HOST", "env-mail.example")
    assert admin.get("/api/ops/integrations").data and _fields_by_key(
        admin.get("/api/ops/integrations").data)["smtp.host"]["value"] == "env-mail.example"
    assert admin.put("/api/ops/integrations", {"key": "smtp.host", "value": "db-mail.example"},
                     format="json").status_code == 200
    assert _fields_by_key(admin.get("/api/ops/integrations").data)["smtp.host"]["value"] == "db-mail.example"
    cleared = admin.put("/api/ops/integrations", {"key": "smtp.host", "value": ""}, format="json")
    assert cleared.status_code == 200
    assert not IntegrationSetting.objects.filter(key="smtp.host").exists()
    assert _fields_by_key(admin.get("/api/ops/integrations").data)["smtp.host"]["value"] == "env-mail.example"
    row = AuditLog.objects.filter(action="integration.update", entity_id="smtp.host").order_by("id").first()
    assert row is not None
    assert row.diff_json.get("value") == "db-mail.example"


@pytest.mark.django_db
def test_put_validation(accounts: dict[str, APIClient]) -> None:
    admin = accounts["admin"]
    assert admin.put("/api/ops/integrations", {"key": "nope.key", "value": "x"}, format="json").status_code == 400
    for bad in ("0", "70000", "abc", 0, 99999):
        resp = admin.put("/api/ops/integrations", {"key": "smtp.port", "value": bad}, format="json")
        assert resp.status_code == 400, bad
    assert admin.put("/api/ops/integrations", {"key": "smtp.port", "value": "587"}, format="json").status_code == 200
    assert _fields_by_key(admin.get("/api/ops/integrations").data)["smtp.port"]["value"] == 587
    bad_bool = admin.put("/api/ops/integrations", {"key": "smtp.enabled", "value": "maybe"}, format="json")
    assert bad_bool.status_code == 400
    for truthy in (True, "true", "1", "yes", "on"):
        assert admin.put("/api/ops/integrations", {"key": "smtp.enabled", "value": truthy},
                         format="json").status_code == 200
    assert _fields_by_key(admin.get("/api/ops/integrations").data)["smtp.enabled"]["value"] is True
    bad_url = admin.put("/api/ops/integrations", {"key": "cmdb.base_url", "value": "ftp://x"}, format="json")
    assert bad_url.status_code == 400
    good_url = admin.put("/api/ops/integrations", {"key": "cmdb.base_url", "value": "https://cmdb.example"},
                         format="json")
    assert good_url.status_code == 200


@pytest.mark.django_db
def test_probe_smtp_requires_to_and_sends(accounts: dict[str, APIClient]) -> None:
    admin = accounts["admin"]
    assert admin.post("/api/ops/integrations/test", {"key": "smtp"}, format="json").status_code == 400
    with mock.patch("apps.sysconfig.views.send_ticket_mail", return_value=1) as sender:
        resp = admin.post("/api/ops/integrations/test", {"key": "smtp", "to": "me@example.com"}, format="json")
    assert resp.status_code == 200
    assert resp.data["ok"] is True
    assert sender.call_args.args[0] == ["me@example.com"]
    with mock.patch("apps.sysconfig.views.send_ticket_mail", return_value=0):
        resp = admin.post("/api/ops/integrations/test", {"key": "smtp", "to": "me@example.com"}, format="json")
    assert resp.data["ok"] is False


@pytest.mark.django_db
def test_probe_wecom_bot(accounts: dict[str, APIClient]) -> None:
    admin = accounts["admin"]
    with mock.patch("apps.sysconfig.views.send_wecom_text", return_value=1):
        resp = admin.post("/api/ops/integrations/test", {"key": "wecom.bot"}, format="json")
    assert resp.status_code == 200
    assert resp.data == {"ok": True, "detail": "测试消息已推送到群"}
    with mock.patch("apps.sysconfig.views.send_wecom_text", return_value=0):
        resp = admin.post("/api/ops/integrations/test", {"key": "wecom.bot"}, format="json")
    assert resp.data["ok"] is False


@pytest.mark.django_db
def test_probe_wecom_login_gettoken_only(accounts: dict[str, APIClient], monkeypatch: pytest.MonkeyPatch) -> None:
    admin = accounts["admin"]
    monkeypatch.delenv("WECOM_CORPID", raising=False)
    monkeypatch.delenv("WECOM_SECRET", raising=False)
    resp = admin.post("/api/ops/integrations/test", {"key": "wecom.login"}, format="json")
    assert resp.status_code == 200
    assert resp.data["ok"] is False
    IntegrationSetting.objects.update_or_create(key="wecom.login_corpid", defaults={"value": "corp123"})
    IntegrationSetting.objects.update_or_create(key="wecom.login_secret", defaults={"value": "sec456"})
    token_resp = mock.Mock()
    token_resp.json.return_value = {"access_token": "tok123", "expires_in": 7200}
    with mock.patch("apps.sysconfig.views.requests.get", return_value=token_resp) as getter:
        resp = admin.post("/api/ops/integrations/test", {"key": "wecom.login"}, format="json")
    assert resp.data["ok"] is True
    assert getter.call_count == 1
    assert "gettoken" in str(getter.call_args.args[0])
    assert "sec456" not in resp.data["detail"]


@pytest.mark.django_db
def test_probe_cmdb_reports_shape_no_db_writes(accounts: dict[str, APIClient]) -> None:
    from apps.assets.models import Asset

    admin = accounts["admin"]
    IntegrationSetting.objects.update_or_create(key="cmdb.base_url", defaults={"value": "https://cmdb.example"})
    page = mock.Mock()
    page.json.return_value = {"results": [{"ip": "10.9.0.1"}], "next": None}
    before = Asset.objects.count()
    with mock.patch("apps.sysconfig.views.requests.get", return_value=page) as getter:
        resp = admin.post("/api/ops/integrations/test", {"key": "cmdb"}, format="json")
    assert resp.status_code == 200
    assert resp.data["ok"] is True
    assert "results" in resp.data["detail"] and "1" in resp.data["detail"]
    assert Asset.objects.count() == before
    assert getter.call_args.args[0] == "https://cmdb.example/assets"


@pytest.mark.django_db
def test_probe_unknown_and_exception_never_500(accounts: dict[str, APIClient]) -> None:
    admin = accounts["admin"]
    assert admin.post("/api/ops/integrations/test", {"key": "ftp"}, format="json").status_code == 400
    IntegrationSetting.objects.update_or_create(key="cmdb.base_url", defaults={"value": "https://cmdb.example"})
    with mock.patch("apps.sysconfig.views.requests.get", side_effect=RuntimeError("boom")):
        resp = admin.post("/api/ops/integrations/test", {"key": "cmdb"}, format="json")
    assert resp.status_code == 200
    assert resp.data == {"ok": False, "detail": "boom"}


@pytest.mark.django_db
def test_field_map_viewer_operator_only(accounts: dict[str, APIClient]) -> None:
    resp = accounts["operator"].get("/api/imports/field-map")
    assert resp.status_code == 200, resp.content
    assert resp.data["version"] == "2"
    assert resp.data["mapping"]["version"] == "2"
    assert {"aliases", "severity_map", "defaults"} <= set(resp.data["mapping"])
    assert accounts["owner"].get("/api/imports/field-map").status_code == 403


@pytest.mark.django_db
def test_store_typed_helpers_and_secret_set() -> None:
    assert cfg.SECRET_KEYS == SECRET_KEYS
    assert cfg.is_set("smtp.password") is False
    IntegrationSetting.objects.update_or_create(key="smtp.port", defaults={"value": "2525"})
    assert cfg.get_int("smtp.port", 0) == 2525
    assert cfg.get_int("smtp.port", 0) != 0
    IntegrationSetting.objects.update_or_create(key="smtp.enabled", defaults={"value": "yes"})
    assert cfg.get_bool("smtp.enabled", False) is True
    assert cfg.get("smtp.host", "fallback-host") == "fallback-host"
    IntegrationSetting.objects.update_or_create(key="smtp.password", defaults={"value": "pw-x"})
    assert cfg.is_set("smtp.password") is True


@pytest.mark.django_db
@override_settings(NOTIFY_ENABLED=True, EMAIL_HOST="smtp.example.com", DEFAULT_FROM_EMAIL="sec@example.com")
def test_mail_configured_db_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.notify.mailer import mail_configured

    monkeypatch.delenv("NOTIFY_ENABLED", raising=False)
    monkeypatch.delenv("EMAIL_HOST", raising=False)
    assert mail_configured() is True
    IntegrationSetting.objects.update_or_create(key="smtp.enabled", defaults={"value": "false"})
    assert mail_configured() is False
    IntegrationSetting.objects.filter(key="smtp.enabled").delete()
    assert mail_configured() is True


@pytest.mark.django_db
def test_wecom_is_configured_db_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.accounts.wecom import is_configured

    monkeypatch.delenv("WECOM_CORPID", raising=False)
    monkeypatch.delenv("WECOM_SECRET", raising=False)
    assert is_configured() is False
    IntegrationSetting.objects.update_or_create(key="wecom.login_corpid", defaults={"value": "corp123"})
    IntegrationSetting.objects.update_or_create(key="wecom.login_secret", defaults={"value": "sec456"})
    assert is_configured() is True


@pytest.mark.django_db
def test_cache_invalidation_put_then_get(accounts: dict[str, APIClient]) -> None:
    admin = accounts["admin"]
    first = admin.put(
        "/api/ops/integrations", {"key": "smtp.host", "value": "cache-a.example"},
        format="json",
    )
    assert first.status_code == 200, first.content
    assert cfg.get("smtp.host", "") == "cache-a.example"
    second = admin.put(
        "/api/ops/integrations", {"key": "smtp.host", "value": "cache-b.example"},
        format="json",
    )
    assert second.status_code == 200, second.content
    assert cfg.get("smtp.host", "") == "cache-b.example"
    body = admin.get("/api/ops/integrations")
    assert body.status_code == 200
    fields = _fields_by_key(body.data)
    assert fields["smtp.host"]["value"] == "cache-b.example"
