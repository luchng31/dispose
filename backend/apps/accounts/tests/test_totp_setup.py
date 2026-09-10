"""TOTP self-service enroll: setup (stateless issue) -> confirm (activate).

Covers: setup returns secret+otpauth_url without persisting; confirm with a
wrong code does not persist (no lockout); correct code persists and login
then requires totp; double enroll is rejected; disable with password clears
and login works without totp again; anonymous access is denied.
"""

from __future__ import annotations

from typing import Any

import pytest
from rest_framework.test import APIClient

from apps.accounts import mfa as mfa_lib
from apps.accounts.models import Role, User

PW: str = "pw-test-only-123"


def _make_user(username: str) -> User:
    return User.objects.create_user(  # type: ignore[arg-type]
        username=username, password=PW, wecom_userid=username, role=Role.OWNER
    )


def _auth(username: str, password: str = PW, **kwargs: Any) -> APIClient:
    client = APIClient()
    login = client.post(
        "/api/auth/local",
        {"username": username, "password": password, **kwargs},
        format="json",
    )
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


@pytest.fixture
def totp_db(db: Any) -> User:
    return _make_user("totp_self")


@pytest.mark.django_db
def test_setup_issues_secret_without_persisting(totp_db: User) -> None:
    client = _auth("totp_self")
    resp = client.post("/api/auth/totp/setup")
    assert resp.status_code == 200, resp.content
    assert resp.data["secret"]
    assert resp.data["otpauth_url"].startswith("otpauth://totp/")
    assert "secret=" in resp.data["otpauth_url"]
    totp_db.refresh_from_db()
    assert not totp_db.totp_secret


@pytest.mark.django_db
def test_confirm_wrong_code_does_not_persist(totp_db: User) -> None:
    client = _auth("totp_self")
    secret: str = str(client.post("/api/auth/totp/setup").data["secret"])
    resp = client.post("/api/auth/totp/confirm", {"secret": secret, "code": "000000"})
    assert resp.status_code == 401
    totp_db.refresh_from_db()
    assert not totp_db.totp_secret


@pytest.mark.django_db
def test_confirm_correct_code_activates_and_login_requires_totp(totp_db: User) -> None:
    client = _auth("totp_self")
    secret: str = str(client.post("/api/auth/totp/setup").data["secret"])
    code: str = mfa_lib.current_code(secret)
    resp = client.post("/api/auth/totp/confirm", {"secret": secret, "code": code})
    assert resp.status_code == 200
    assert resp.data == {"enrolled": True}
    naked = APIClient().post(
        "/api/auth/local", {"username": "totp_self", "password": PW}, format="json"
    )
    assert naked.status_code == 401
    authed = APIClient().post(
        "/api/auth/local",
        {"username": "totp_self", "password": PW, "totp": mfa_lib.current_code(secret)},
        format="json",
    )
    assert authed.status_code == 200


@pytest.mark.django_db
def test_double_enroll_rejected(totp_db: User) -> None:
    client = _auth("totp_self")
    secret: str = str(client.post("/api/auth/totp/setup").data["secret"])
    client.post("/api/auth/totp/confirm", {"secret": secret, "code": mfa_lib.current_code(secret)})
    assert client.post("/api/auth/totp/setup").status_code == 400
    assert (
        client.post(
            "/api/auth/totp/confirm", {"secret": secret, "code": mfa_lib.current_code(secret)}
        ).status_code
        == 400
    )


@pytest.mark.django_db
def test_disable_with_password_clears(totp_db: User) -> None:
    client = _auth("totp_self")
    secret: str = str(client.post("/api/auth/totp/setup").data["secret"])
    client.post("/api/auth/totp/confirm", {"secret": secret, "code": mfa_lib.current_code(secret)})
    assert client.post("/api/auth/totp/disable", {"password": "wrong"}).status_code == 400
    resp = client.post("/api/auth/totp/disable", {"password": PW})
    assert resp.status_code == 200
    assert resp.data == {"enrolled": False}
    totp_db.refresh_from_db()
    assert not totp_db.totp_secret
    plain = APIClient().post(
        "/api/auth/local", {"username": "totp_self", "password": PW}, format="json"
    )
    assert plain.status_code == 200


@pytest.mark.django_db
def test_anonymous_denied(totp_db: User) -> None:
    anon = APIClient()
    assert anon.post("/api/auth/totp/setup").status_code in (401, 403)
    assert anon.post("/api/auth/totp/confirm", {"secret": "x", "code": "1"}).status_code in (401, 403)
    assert anon.post("/api/auth/totp/disable", {"password": PW}).status_code in (401, 403)
