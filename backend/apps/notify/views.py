from __future__ import annotations

from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.notify.mailer import (
    mail_configured,
    send_ticket_mail,
    smtp_enabled,
    smtp_from,
    smtp_host,
    smtp_port,
    smtp_use_ssl,
    smtp_use_tls,
)
from apps.notify.wecom_bot import send_wecom_text, wecom_configured
from apps.tickets.views import IsOperator


def _actor(request: Request) -> User:
    user: object = request.user
    assert isinstance(user, User)
    return user


class NotifyStatusView(APIView):
    """GET /api/ops/notify/status (operator only, no secrets exposed)."""

    permission_classes = [IsAuthenticated, IsOperator]

    def get(self, request: Request) -> Response:
        del request
        return Response(
            {
                "enabled": smtp_enabled(),
                "configured": mail_configured(),
                "host": smtp_host(),
                "port": smtp_port(),
                "from": smtp_from(),
                "use_ssl": smtp_use_ssl(),
                "use_tls": smtp_use_tls(),
                "wecom_configured": wecom_configured(),
            }
        )


class NotifyTestView(APIView):
    """POST /api/ops/notify/test {to?, channel?} (operator only).

    channel=mail (default) sends one test mail to ``to``;
    channel=wecom posts one test message to the group bot webhook.
    """

    permission_classes = [IsAuthenticated, IsOperator]

    def post(self, request: Request) -> Response:
        channel = str(request.data.get("channel", "mail") or "mail").strip().lower()
        if channel == "wecom":
            sent = send_wecom_text("来自漏洞工单系统的测试消息：企微群机器人对接成功。")
            return Response({"sent": sent, "channel": "wecom", "configured": wecom_configured()})
        to = str(request.data.get("to", "") or "").strip()
        if not to:
            return Response({"detail": "缺少 to（收件邮箱）"}, status=400)
        sent = send_ticket_mail(
            [to],
            "测试邮件",
            "这是一封来自漏洞工单系统的测试邮件，收到即表示企业邮箱对接成功。",
        )
        return Response({"sent": sent, "channel": "mail", "configured": mail_configured()})
