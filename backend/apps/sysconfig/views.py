"""Admin-only integration settings API (page-editable, no backend restart).

Endpoints (all IsAdminRole; secrets never leave the server in cleartext):
  GET /api/ops/integrations      -> grouped fields + masked secret flags
  PUT /api/ops/integrations      -> {key, value} upsert / clear-to-env
  POST /api/ops/integrations/test -> {ok, detail} connectivity probes

Writes mirror the UserAdminDetailView._user_audit manual-AuditLog pattern:
action="integration.update", entity="integration_setting", entity_id=key,
secret values masked as "****" in diff_json (never plaintext).
"""

from __future__ import annotations

from typing import Any

import requests
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.accounts.permissions import IsAdminRole
from apps.audit.models import AuditLog
from apps.notify.mailer import send_ticket_mail
from apps.notify.wecom_bot import send_wecom_text
from apps.sysconfig import store as cfg
from apps.sysconfig.models import IntegrationSetting

MASKED = "****"

FIELD_META: dict[str, dict[str, Any]] = {
    "smtp.enabled": {"label": "启用邮件通知", "secret": False, "kind": "bool", "hint": "NOTIFY_ENABLED"},
    "smtp.host": {"label": "SMTP 服务器", "secret": False, "kind": "str", "hint": "EMAIL_HOST，如 smtp.exmail.qq.com"},
    "smtp.port": {"label": "SMTP 端口", "secret": False, "kind": "int", "hint": "EMAIL_PORT，1-65535"},
    "smtp.user": {"label": "SMTP 账号", "secret": False, "kind": "str", "hint": "EMAIL_HOST_USER"},
    "smtp.password": {
        "label": "SMTP 密码", "secret": True, "kind": "str",
        "hint": "EMAIL_HOST_PASSWORD，留空=保持不变",
    },
    "smtp.use_ssl": {"label": "SMTP SSL", "secret": False, "kind": "bool", "hint": "EMAIL_USE_SSL，465 端口常用"},
    "smtp.use_tls": {"label": "SMTP TLS", "secret": False, "kind": "bool", "hint": "EMAIL_USE_TLS，587 端口常用"},
    "smtp.from": {"label": "发件人地址", "secret": False, "kind": "str", "hint": "DEFAULT_FROM_EMAIL"},
    "smtp.subject_prefix": {"label": "邮件主题前缀", "secret": False, "kind": "str", "hint": "NOTIFY_SUBJECT_PREFIX"},
    "wecom.login_corpid": {"label": "企微 CorpId", "secret": False, "kind": "str", "hint": "WECOM_CORPID，扫码登录用"},
    "wecom.login_secret": {
        "label": "企微 Secret", "secret": True, "kind": "str",
        "hint": "WECOM_SECRET，留空=保持不变",
    },
    "wecom.bot_webhook": {
        "label": "群机器人 Webhook", "secret": True, "kind": "str",
        "hint": "NOTIFY_WECOM_WEBHOOK，留空=保持不变",
    },
    "cmdb.base_url": {
        "label": "CMDB 地址", "secret": False, "kind": "url",
        "hint": "CMDB_BASE_URL，须以 http(s):// 开头",
    },
    "cmdb.token": {"label": "CMDB Token", "secret": True, "kind": "str", "hint": "CMDB_TOKEN，留空=保持不变"},
}

GROUPS: list[dict[str, Any]] = [
    {"id": "smtp", "label": "企业邮箱（SMTP）", "keys": [
        "smtp.enabled", "smtp.host", "smtp.port", "smtp.user", "smtp.password",
        "smtp.use_ssl", "smtp.use_tls", "smtp.from", "smtp.subject_prefix",
    ]},
    {"id": "wecom", "label": "企微", "keys": [
        "wecom.login_corpid", "wecom.login_secret", "wecom.bot_webhook",
    ]},
    {"id": "cmdb", "label": "CMDB", "keys": ["cmdb.base_url", "cmdb.token"]},
]

TEST_TARGETS: frozenset[str] = frozenset({"smtp", "wecom.bot", "wecom.login", "cmdb"})


def _actor(request: Request) -> User | None:
    user: object = request.user
    return user if isinstance(user, User) else None


def _field_value(key: str) -> Any:
    kind = str(FIELD_META[key].get("kind", "str"))
    if kind == "bool":
        return cfg.get_bool(key, False)
    if kind == "int":
        return cfg.get_int(key, 0)
    return cfg.get(key, "")


def _field_configured(key: str, value: Any) -> bool:
    kind = str(FIELD_META[key].get("kind", "str"))
    if kind == "bool":
        return bool(value)
    if kind == "int":
        return int(value) > 0
    return bool(str(value).strip())


def _serialize_field(key: str) -> dict[str, Any]:
    meta = FIELD_META[key]
    if bool(meta.get("secret")):
        return {
            "key": key,
            "label": str(meta.get("label", key)),
            "secret": True,
            "configured": cfg.is_set(key),
            "hint": str(meta.get("hint", "")),
        }
    value = _field_value(key)
    return {
        "key": key,
        "label": str(meta.get("label", key)),
        "secret": False,
        "value": value,
        "configured": _field_configured(key, value),
        "hint": str(meta.get("hint", "")),
    }


def _audit_write(request: Request, key: str, shown_value: str, configured: bool) -> None:
    AuditLog.objects.create(
        actor=_actor(request),
        action="integration.update",
        entity="integration_setting",
        entity_id=key,
        diff_json={"key": key, "value": shown_value, "configured": configured},
        ip_addr=str(request.META.get("REMOTE_ADDR", "")),
    )


def _validate_value(key: str, value: Any) -> tuple[str, Response | None]:
    """Normalize an incoming PUT value; returns (stored_str, error_response)."""
    kind = str(FIELD_META[key].get("kind", "str"))
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif value is None:
        text = ""
    else:
        text = str(value)
    if kind == "int":
        try:
            number = int(text.strip())
        except (ValueError, TypeError):
            return "", Response({"detail": f"{key} 需为 1-65535 的整数"}, status=status.HTTP_400_BAD_REQUEST)
        if not 1 <= number <= 65535:
            return "", Response({"detail": f"{key} 需为 1-65535 的整数"}, status=status.HTTP_400_BAD_REQUEST)
        return str(number), None
    if kind == "bool":
        needle = text.strip().lower()
        if needle not in cfg.BOOL_ACCEPTED:
            return "", Response(
                {"detail": f"{key} 需为布尔值（true/false/1/0/yes/no/on/off）"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return ("true" if needle in {"1", "true", "yes", "on"} else "false"), None
    if key in cfg.URL_KEYS and text.strip():
        lowered = text.strip().lower()
        if not (lowered.startswith("http://") or lowered.startswith("https://")):
            return "", Response(
                {"detail": f"{key} 须以 http:// 或 https:// 开头"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return text.strip(), None
    return text, None


def _scrub(detail: str) -> str:
    """Strip any effective secret material from a probe detail string."""
    text = str(detail)
    for key in cfg.SECRET_KEYS:
        secret = cfg.get(key, "")
        if secret and len(secret) >= 3:
            text = text.replace(secret, MASKED)
    return text


class IntegrationListUpdateView(APIView):
    """GET/PUT /api/ops/integrations (admin only)."""

    permission_classes = [IsAuthenticated, IsAdminRole]

    def get(self, request: Request) -> Response:
        del request
        groups = [
            {"id": group["id"], "label": group["label"],
             "fields": [_serialize_field(key) for key in group["keys"]]}
            for group in GROUPS
        ]
        return Response({"groups": groups})

    def put(self, request: Request) -> Response:
        key = str(request.data.get("key", "") or "").strip()
        if key not in FIELD_META:
            return Response(
                {"detail": f"未知配置项：{key}", "allowed": sorted(FIELD_META)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        raw_value: Any = request.data.get("value", "")
        stored, err = _validate_value(key, raw_value)
        if err is not None:
            return err
        secret = bool(FIELD_META[key].get("secret"))
        if secret and stored == "":
            configured = cfg.is_set(key)
            return Response({"key": key, "configured": configured})
        if stored == "":
            IntegrationSetting.objects.filter(key=key).delete()
            cfg.invalidate_config(key)
            effective = _field_value(key)
            configured = _field_configured(key, effective)
            _audit_write(request, key, "(cleared, fallback to env)", configured)
            return Response({"key": key, "configured": configured})
        IntegrationSetting.objects.update_or_create(key=key, defaults={"value": stored})
        cfg.invalidate_config(key)
        configured = _field_configured(key, _field_value(key))
        _audit_write(request, key, MASKED if secret else stored, configured)
        return Response({"key": key, "configured": configured})


class IntegrationTestView(APIView):
    """POST /api/ops/integrations/test {key, to?} (admin only, never 500)."""

    permission_classes = [IsAuthenticated, IsAdminRole]

    def post(self, request: Request) -> Response:
        key = str(request.data.get("key", "") or "").strip()
        if key not in TEST_TARGETS:
            return Response(
                {"detail": f"未知测试目标：{key}", "allowed": sorted(TEST_TARGETS)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            if key == "smtp":
                return self._test_smtp(request)
            if key == "wecom.bot":
                return self._test_wecom_bot()
            if key == "wecom.login":
                return self._test_wecom_login()
            return self._test_cmdb()
        except Exception as exc:
            return Response({"ok": False, "detail": _scrub(str(exc) or "测试失败")})

    def _test_smtp(self, request: Request) -> Response:
        to = str(request.data.get("to", "") or "").strip()
        if not to:
            return Response({"detail": "缺少 to（收件邮箱）"}, status=status.HTTP_400_BAD_REQUEST)
        sent = send_ticket_mail(
            [to],
            "测试邮件",
            "这是一封来自漏洞工单系统的测试邮件，收到即表示企业邮箱对接成功。",
        )
        if sent > 0:
            return Response({"ok": True, "detail": f"测试邮件已发送至 {to}"})
        return Response({"ok": False, "detail": "未发出：SMTP 未配置或发送失败"})

    def _test_wecom_bot(self) -> Response:
        sent = send_wecom_text("来自漏洞工单系统的测试消息：企微群机器人对接成功。")
        if sent == 1:
            return Response({"ok": True, "detail": "测试消息已推送到群"})
        return Response({"ok": False, "detail": "未发出：Webhook 未配置或被企微拒绝"})

    def _test_wecom_login(self) -> Response:
        corpid = cfg.get("wecom.login_corpid", "")
        secret = cfg.get("wecom.login_secret", "")
        if not corpid or not secret:
            return Response({"ok": False, "detail": "未配置：请先填写企微 CorpId 与 Secret"})
        resp = requests.get(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
            params={"corpid": corpid, "corpsecret": secret},
            timeout=5,
        )
        body: Any = resp.json()
        token = str(body.get("access_token", "") or "") if isinstance(body, dict) else ""
        if token:
            return Response({"ok": True, "detail": "企微凭证有效：gettoken 成功"})
        return Response({"ok": False, "detail": _scrub(f"企微凭证无效：{body}")})

    def _test_cmdb(self) -> Response:
        base = cfg.get("cmdb.base_url", "").rstrip("/")
        token = cfg.get("cmdb.token", "")
        if not base:
            return Response({"ok": False, "detail": "未配置：请先填写 CMDB 地址"})
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(f"{base}/assets", params={"page_size": 1}, headers=headers, timeout=10)
        payload: Any = resp.json()
        items: list[Any] = []
        shape = "unknown"
        if isinstance(payload, list):
            items, shape = payload, "list"
        elif isinstance(payload, dict):
            for name in ("results", "items", "data"):
                candidate = payload.get(name)
                if isinstance(candidate, list):
                    items, shape = candidate, name
                    break
        return Response({"ok": True, "detail": f"CMDB 连通正常：{shape} 返回 {len(items)} 条"})
