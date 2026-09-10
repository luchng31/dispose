"""Django settings for the vuln-ticket system (Wave1 scaffold, Task1).

Secrets come from the environment only. NEVER hardcode passwords.
Production defaults target PostgreSQL 16 + Redis; set DB_ENGINE=sqlite
for the local scaffold test path when PG is unavailable.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw: str = os.environ.get(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


SECRET_KEY: str = _env("DJANGO_SECRET_KEY", "django-insecure-scaffold-only-change-me")
DEBUG: bool = _env("DJANGO_DEBUG", "false").lower() in {"1", "true", "yes", "on"}
ALLOWED_HOSTS: list[str] = [h for h in _env("DJANGO_ALLOWED_HOSTS", "*").split(",") if h]

INSTALLED_APPS: list[str] = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "apps.accounts",
    "apps.assets",
    "apps.tickets",
    "apps.imports",
    "apps.cmdb",
    "apps.audit",
    "apps.notify",
    "apps.sysconfig",
]

MIDDLEWARE: list[str] = [
    "config.cors.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.audit.middleware.AuditActorMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES: list[dict[str, object]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# --- Database: PostgreSQL 16 by default, sqlite only via explicit opt-in ---
# pytest-django imports this module before any conftest.py runs, so a conftest
# cannot default the env in time; default to sqlite inside the test process
# instead. An explicitly exported DB_ENGINE always wins (e.g. CI on real PG).
_db_engine_raw: str | None = os.environ.get("DB_ENGINE")
if _db_engine_raw is None and "pytest" in sys.modules:
    _db_engine_raw = "sqlite"
DB_ENGINE: str = (_db_engine_raw or "postgres").lower()
if DB_ENGINE == "sqlite":
    DATABASES: dict[str, dict[str, object]] = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": _env("SQLITE_PATH", str(BASE_DIR / "db.sqlite3")),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _env("POSTGRES_DB", "vulntickets"),
            "USER": _env("POSTGRES_USER", "vuln"),
            "PASSWORD": _env("POSTGRES_PASSWORD", ""),
            "HOST": _env("POSTGRES_HOST", "localhost"),
            "PORT": str(_env_int("POSTGRES_PORT", 5432)),
            "CONN_MAX_AGE": _env_int("DB_CONN_MAX_AGE", 60),
        }
    }

# --- Redis / cache ---
REDIS_URL: str = _env("REDIS_URL", "redis://localhost:6379/0")
# sqlite (local/dev/test) has no Redis: fall back to LocMem so login works
_CACHES: dict[str, dict[str, object]] = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    }
}
if DB_ENGINE == "sqlite":
    _CACHES["default"] = {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "vuln-lockout",
    }
CACHES: dict[str, dict[str, object]] = _CACHES

# --- Celery (broker + beat live in Wave4 deploy; settings wired now) ---
CELERY_BROKER_URL: str = _env("CELERY_BROKER_URL", "redis://localhost:6379/1")
CELERY_RESULT_BACKEND: str = _env("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
CELERY_TIMEZONE: str = _env("CELERY_TIMEZONE", "Asia/Shanghai")
CELERY_TASK_ALWAYS_EAGER: bool = _env("CELERY_TASK_ALWAYS_EAGER", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# --- DRF + JWT (Wave2 adds the authenticator; contract declared here) ---
REST_FRAMEWORK: dict[str, object] = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.accounts.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}
JWT_ALGORITHM: str = _env("JWT_ALGORITHM", "HS256")
JWT_SECRET_KEY: str = _env("JWT_SECRET_KEY", "")
JWT_ACCESS_TOKEN_LIFETIME: timedelta = timedelta(
    minutes=_env_int("JWT_ACCESS_MINUTES", 60)
)
JWT_REFRESH_TOKEN_LIFETIME: timedelta = timedelta(
    days=_env_int("JWT_REFRESH_DAYS", 7)
)

AUTH_PASSWORD_VALIDATORS: list[dict[str, object]] = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

AUTH_USER_MODEL = "accounts.User"

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "Asia/Shanghai"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
SERVE_MEDIA: bool = _env("SERVE_MEDIA", "false").lower() in {"1", "true", "yes", "on"}

# --- Email (corporate SMTP; all notify hooks no-op when NOTIFY_ENABLED off) ---
EMAIL_BACKEND: str = _env(
    "EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend"
)
EMAIL_HOST: str = _env("EMAIL_HOST", "")
EMAIL_PORT: int = _env_int("EMAIL_PORT", 465)
EMAIL_HOST_USER: str = _env("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD: str = _env("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_SSL: bool = _env("EMAIL_USE_SSL", "true").lower() in {"1", "true", "yes", "on"}
EMAIL_USE_TLS: bool = _env("EMAIL_USE_TLS", "false").lower() in {"1", "true", "yes", "on"}
DEFAULT_FROM_EMAIL: str = _env("DEFAULT_FROM_EMAIL", "")
NOTIFY_ENABLED: bool = _env("NOTIFY_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
NOTIFY_SUBJECT_PREFIX: str = _env("NOTIFY_SUBJECT_PREFIX", "【漏洞工单】")
# WeCom group bot (群机器人 webhook, qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...)
NOTIFY_WECOM_WEBHOOK: str = _env("NOTIFY_WECOM_WEBHOOK", "")

# --- Login brute-force lockout: N failures per username -> lockout window ---
LOGIN_MAX_FAILURES: int = _env_int("LOGIN_MAX_FAILURES", 10)
LOGIN_LOCKOUT_SECONDS: int = _env_int("LOGIN_LOCKOUT_SECONDS", 900)

# --- CORS (dev browsers on :5173 calling API on :8000; prod web+api split) ---
CORS_ALLOWED_ORIGINS: str = _env(
    "CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
)

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
