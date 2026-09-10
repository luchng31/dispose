"""Refresh rotation: single-use refresh tokens with reuse detection.

Covers: login issues both tokens; refresh rotates (new pair works, old
refresh replay -> 401); access token rejected as refresh and vice versa;
tampered/expired refresh -> 401; logout revokes; password change silently
invalidates outstanding refresh tokens; missing field -> 422.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from django.conf import settings
from rest_framework.test import APIClient

from apps.accounts.models import Role, User

PW: str = "pw-test-only-123"


def _make_user(username: str) -> User:
    return User.objects.create_user(  # type: ignore[arg-type]
        username=username, password=PW, wecom_userid=username, role=Role.OWNER
    )


def _login(username: str, password: str = PW) -> dict[str, Any]:
    resp = APIClient().post(
        "/api/auth/local",
        {"username": username, "password": password},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    return dict(resp.data)


@pytest.fixture
def refresh_db(db: Any) -> User:
    return _make_user("refresh_user")


@pytest.mark.django_db
def test_login_issues_token_pair(refresh_db: User) -> None:
    body = _login("refresh_user")
    assert body["jwt"]
    assert body["refresh_token"]
    assert body["refresh_token"] != body["jwt"]


@pytest.mark.django_db
def test_refresh_rotates_and_old_replay_rejected(refresh_db: User) -> None:
    first = _login("refresh_user")["refresh_token"]
    anon = APIClient()
    second = anon.post("/api/auth/refresh", {"refresh_token": first}, format="json")
    assert second.status_code == 200, second.content
    assert second.data["refresh_token"] != first
    me = APIClient()
    me.credentials(HTTP_AUTHORIZATION=f"Bearer {second.data['jwt']}")
    assert me.get("/api/auth/me").status_code == 200
    replay = anon.post("/api/auth/refresh", {"refresh_token": first}, format="json")
    assert replay.status_code == 401


@pytest.mark.django_db
def test_token_type_confusion_rejected(refresh_db: User) -> None:
    body = _login("refresh_user")
    anon = APIClient()
    assert (
        anon.post("/api/auth/refresh", {"refresh_token": body["jwt"]}, format="json").status_code
        == 401
    )
    bearer = APIClient()
    bearer.credentials(HTTP_AUTHORIZATION=f"Bearer {body['refresh_token']}")
    assert bearer.get("/api/auth/me").status_code in (401, 403)


@pytest.mark.django_db
def test_tampered_and_expired_rejected(refresh_db: User) -> None:
    anon = APIClient()
    assert anon.post("/api/auth/refresh", {"refresh_token": "x.y.z"}, format="json").status_code == 401
    now = datetime.now(UTC)
    expired = jwt.encode(
        {
            "uid": refresh_db.pk,
            "username": "refresh_user",
            "role": Role.OWNER,
            "type": "refresh",
            "jti": "expired-jti",
            "pwd_mark": "0" * 16,
            "iat": int((now - timedelta(days=8)).timestamp()),
            "exp": int((now - timedelta(days=1)).timestamp()),
        },
        str(settings.SECRET_KEY),
        algorithm="HS256",
    )
    assert anon.post("/api/auth/refresh", {"refresh_token": expired}, format="json").status_code == 401
    assert anon.post("/api/auth/refresh", {}, format="json").status_code == 422


@pytest.mark.django_db
def test_logout_revokes_refresh(refresh_db: User) -> None:
    body = _login("refresh_user")
    authed = APIClient()
    authed.credentials(HTTP_AUTHORIZATION=f"Bearer {body['jwt']}")
    out = authed.post("/api/auth/logout", {"refresh_token": body["refresh_token"]}, format="json")
    assert out.status_code == 200
    assert out.data == {"logged_out": True}
    anon = APIClient()
    assert (
        anon.post(
            "/api/auth/refresh", {"refresh_token": body["refresh_token"]}, format="json"
        ).status_code
        == 401
    )


@pytest.mark.django_db
def test_password_change_invalidates_refresh(refresh_db: User) -> None:
    body = _login("refresh_user")
    authed = APIClient()
    authed.credentials(HTTP_AUTHORIZATION=f"Bearer {body['jwt']}")
    changed = authed.post(
        "/api/auth/change-password",
        {"old_password": PW, "new_password": "pw-test-only-456"},
        format="json",
    )
    assert changed.status_code == 200
    assert changed.data["refresh_token"] != body["refresh_token"]
    anon = APIClient()
    assert (
        anon.post(
            "/api/auth/refresh", {"refresh_token": body["refresh_token"]}, format="json"
        ).status_code
        == 401
    )
    fresh = anon.post(
        "/api/auth/refresh",
        {"refresh_token": changed.data["refresh_token"]},
        format="json",
    )
    assert fresh.status_code == 200
