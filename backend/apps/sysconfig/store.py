"""DB-backed integration settings with env fallback (edit without restart).

Precedence: IntegrationSetting DB row (present and non-empty) wins, else the
mapped ``os.environ`` value, else the caller-supplied default. This mirrors
the SlaPolicy table-over-fallback pattern (see apps.tickets.sla): when no DB
rows exist the behaviour is exactly the old env/settings behaviour.

Callers pass their Django-settings value as ``default`` so ``override_settings``
in tests keeps working::

    store.get("smtp.host", getattr(settings, "EMAIL_HOST", ""))

DB failures (table missing mid-migration, etc.) fall back silently with a
warning — the request path must never crash on a config lookup.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

#: Keys whose values are secrets: never returned by the API, never audited.
SECRET_KEYS: frozenset[str] = frozenset(
    {"smtp.password", "wecom.login_secret", "wecom.bot_webhook", "cmdb.token"}
)

#: Integration key -> env var providing the fallback default.
ENV_MAP: dict[str, str] = {
    "smtp.enabled": "NOTIFY_ENABLED",
    "smtp.host": "EMAIL_HOST",
    "smtp.port": "EMAIL_PORT",
    "smtp.user": "EMAIL_HOST_USER",
    "smtp.password": "EMAIL_HOST_PASSWORD",
    "smtp.use_ssl": "EMAIL_USE_SSL",
    "smtp.use_tls": "EMAIL_USE_TLS",
    "smtp.from": "DEFAULT_FROM_EMAIL",
    "smtp.subject_prefix": "NOTIFY_SUBJECT_PREFIX",
    "wecom.login_corpid": "WECOM_CORPID",
    "wecom.login_secret": "WECOM_SECRET",
    "wecom.bot_webhook": "NOTIFY_WECOM_WEBHOOK",
    "cmdb.base_url": "CMDB_BASE_URL",
    "cmdb.token": "CMDB_TOKEN",
}

ALLOWED_KEYS: frozenset[str] = frozenset(ENV_MAP)

BOOL_KEYS: frozenset[str] = frozenset({"smtp.enabled", "smtp.use_ssl", "smtp.use_tls"})
INT_KEYS: frozenset[str] = frozenset({"smtp.port"})
URL_KEYS: frozenset[str] = frozenset({"cmdb.base_url", "wecom.bot_webhook"})

_TRUE_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES: frozenset[str] = frozenset({"0", "false", "no", "off", ""})

#: Accepted spellings for boolean writes (case-insensitive) + real booleans.
BOOL_ACCEPTED: frozenset[str] = frozenset(_TRUE_VALUES | _FALSE_VALUES - {""})


def parse_bool(raw: object) -> bool:
    """Parse truthy config spellings; anything else (incl. garbage) is False."""
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in _TRUE_VALUES


_CACHE_TTL: int = 60


def _cache_key(key: str) -> str:
    return f"cfgv1:{key}"


def invalidate_config(key: str) -> None:
    try:
        from django.core.cache import cache

        cache.delete(_cache_key(key))
    except Exception:
        pass


def _db_value_uncached(key: str) -> str | None:
    try:
        from apps.sysconfig.models import IntegrationSetting

        row = IntegrationSetting.objects.filter(key=key).first()
    except Exception as exc:
        logger.warning("integration_setting lookup failed for %s: %s", key, exc)
        return None
    if row is None:
        return None
    text = str(row.value or "")
    return text if text != "" else None


def _db_value(key: str) -> str | None:
    """Raw DB row value, or None when absent/empty/unreadable (60s cached)."""
    ck = _cache_key(key)
    try:
        from django.core.cache import cache

        entry = cache.get(ck)
    except Exception:
        entry = None
    if isinstance(entry, dict) and "v" in entry:
        return entry["v"]
    value = _db_value_uncached(key)
    try:
        from django.core.cache import cache

        cache.set(ck, {"v": value}, timeout=_CACHE_TTL)
    except Exception:
        pass
    return value


def get(key: str, default: str = "") -> str:
    """Effective value for ``key``: DB row > os.environ > ``default``."""
    hit = _db_value(key)
    if hit is not None:
        return hit
    env_name = ENV_MAP.get(key, "")
    if env_name:
        env_val = os.environ.get(env_name, "")
        if env_val != "":
            return env_val
    return default


def get_int(key: str, default: int = 0) -> int:
    """Effective integer value; ``default`` when absent or unparsable."""
    raw = get(key, "")
    if raw == "":
        return default
    try:
        return int(str(raw).strip())
    except (ValueError, TypeError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    """Effective boolean value; ``default`` only when nothing is set anywhere."""
    hit = _db_value(key)
    if hit is not None:
        return parse_bool(hit)
    env_name = ENV_MAP.get(key, "")
    if env_name:
        env_val = os.environ.get(env_name, "")
        if env_val != "":
            return parse_bool(env_val)
    return default


def is_set(key: str) -> bool:
    """True when the effective value for ``key`` is non-blank."""
    return bool(get(key, "").strip())


__all__ = [
    "ALLOWED_KEYS",
    "BOOL_ACCEPTED",
    "BOOL_KEYS",
    "ENV_MAP",
    "INT_KEYS",
    "SECRET_KEYS",
    "URL_KEYS",
    "get",
    "get_bool",
    "get_int",
    "invalidate_config",
    "is_set",
    "parse_bool",
]
