from __future__ import annotations

import logging

from django.conf import settings
from django.core.mail import get_connection
from django.core.mail.message import EmailMessage

from apps.sysconfig import store as cfg

logger = logging.getLogger(__name__)


def smtp_enabled() -> bool:
    return cfg.get_bool("smtp.enabled", bool(getattr(settings, "NOTIFY_ENABLED", False)))


def smtp_host() -> str:
    return cfg.get("smtp.host", str(getattr(settings, "EMAIL_HOST", "")))


def smtp_port() -> int:
    default: int = 465
    try:
        default = int(getattr(settings, "EMAIL_PORT", 465))
    except (TypeError, ValueError):
        default = 465
    return cfg.get_int("smtp.port", default)


def smtp_user() -> str:
    return cfg.get("smtp.user", str(getattr(settings, "EMAIL_HOST_USER", "")))


def smtp_password() -> str:
    return cfg.get("smtp.password", str(getattr(settings, "EMAIL_HOST_PASSWORD", "")))


def smtp_use_ssl() -> bool:
    return cfg.get_bool("smtp.use_ssl", bool(getattr(settings, "EMAIL_USE_SSL", False)))


def smtp_use_tls() -> bool:
    return cfg.get_bool("smtp.use_tls", bool(getattr(settings, "EMAIL_USE_TLS", False)))


def smtp_from() -> str:
    return cfg.get("smtp.from", str(getattr(settings, "DEFAULT_FROM_EMAIL", "")))


def smtp_subject_prefix() -> str:
    return cfg.get("smtp.subject_prefix", str(getattr(settings, "NOTIFY_SUBJECT_PREFIX", "")))


def mail_configured() -> bool:
    return bool(smtp_enabled() and smtp_host() and smtp_from())


def send_ticket_mail(to: list[str], subject: str, body: str) -> int:
    """Send one ticket notification email. Never raises; returns sent count."""
    addrs = [a.strip() for a in to if a and a.strip()]
    if not addrs:
        return 0
    if not mail_configured():
        logger.info("notify skipped (SMTP not configured): %s -> %s", subject, addrs)
        return 0
    prefix = smtp_subject_prefix()
    try:
        connection = get_connection(
            backend=str(getattr(settings, "EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")),
            host=smtp_host(),
            port=smtp_port(),
            username=smtp_user(),
            password=smtp_password(),
            use_ssl=smtp_use_ssl(),
            use_tls=smtp_use_tls(),
            fail_silently=False,
        )
        message = EmailMessage(f"{prefix}{subject}", body, smtp_from(), addrs, connection=connection)
        return message.send()
    except Exception:
        logger.exception("notify failed: %s -> %s", subject, addrs)
        return 0


def role_emails(*roles: str) -> list[str]:
    from apps.accounts.models import User

    return list(
        User.objects.filter(role__in=roles, is_active=True)
        .exclude(email="")
        .values_list("email", flat=True)
    )


def user_email(user: object) -> str:
    return str(getattr(user, "email", "") or "").strip()


def ticket_line(ticket: object) -> str:
    get = getattr
    return (
        f"工单 #{get(ticket, 'pk', '?')}｜{get(ticket, 'ip', '')}"
        f":{get(ticket, 'port', '')}｜{get(ticket, 'plugin_name', '') or get(ticket, 'cve', '')}"
        f"｜等级{get(ticket, 'severity', '')}｜状态{get(ticket, 'state', '')}"
        f"｜SLA到期{get(ticket, 'sla_due_at', '')}"
    )
