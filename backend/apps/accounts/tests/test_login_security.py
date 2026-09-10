"""P1 auth hardening: brute-force lockout + self-service password change.

DB_ENGINE=sqlite; cache is LocMem (cleared per test to avoid cross-test
lockout leaks).
"""

from __future__ import annotations

from typing import Any

import pytest
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APIClient

from apps.accounts.models import Role, User

PW: str = "pw-test-only-123"


def _make_user(username: str, role: str, **kwargs: Any) -> User:
    return User.objects.create_user(  # type: ignore[arg-type]
        username=username, password=PW, wecom_userid=username, role=role, **kwargs
    )


@pytest.fixture
def _clean_cache() -> None:
    cache.clear()


@pytest.mark.django_db
@override_settings(LOGIN_MAX_FAILURES=3, LOGIN_LOCKOUT_SECONDS=900)
def test_lockout_after_max_failures(_clean_cache: None) -> None:
    _make_user("sec_locked", Role.OWNER)
    client = APIClient()
    for _ in range(3):
        resp = client.post(
            "/api/auth/local", {"username": "sec_locked", "password": "wrong"}, format="json"
        )
        assert resp.status_code == 401
    resp = client.post(
        "/api/auth/local", {"username": "sec_locked", "password": PW}, format="json"
    )
    assert resp.status_code == 429


@pytest.mark.django_db
@override_settings(LOGIN_MAX_FAILURES=3, LOGIN_LOCKOUT_SECONDS=900)
def test_lockout_is_per_username(_clean_cache: None) -> None:
    _make_user("sec_locked2", Role.OWNER)
    _make_user("sec_other", Role.OWNER)
    client = APIClient()
    for _ in range(3):
        client.post(
            "/api/auth/local", {"username": "sec_locked2", "password": "wrong"}, format="json"
        )
    ok = client.post(
        "/api/auth/local", {"username": "sec_other", "password": PW}, format="json"
    )
    assert ok.status_code == 200


@pytest.mark.django_db
@override_settings(LOGIN_MAX_FAILURES=3, LOGIN_LOCKOUT_SECONDS=900)
def test_success_resets_failure_counter(_clean_cache: None) -> None:
    _make_user("sec_reset", Role.OWNER)
    client = APIClient()
    for _ in range(2):
        client.post(
            "/api/auth/local", {"username": "sec_reset", "password": "wrong"}, format="json"
        )
    ok = client.post(
        "/api/auth/local", {"username": "sec_reset", "password": PW}, format="json"
    )
    assert ok.status_code == 200
    for _ in range(2):
        client.post(
            "/api/auth/local", {"username": "sec_reset", "password": "wrong"}, format="json"
        )
    still_ok = client.post(
        "/api/auth/local", {"username": "sec_reset", "password": PW}, format="json"
    )
    assert still_ok.status_code == 200


@pytest.mark.django_db
def test_change_password_ok_and_relogin(_clean_cache: None) -> None:
    user = _make_user("sec_changer", Role.OWNER)
    client = APIClient()
    client.force_authenticate(user)
    resp = client.post(
        "/api/auth/change-password",
        {"old_password": PW, "new_password": "NewPassword-9x"},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    fresh = APIClient()
    fresh.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['jwt']}")
    me = fresh.get("/api/auth/me")
    assert me.status_code == 200
    old_login = APIClient().post(
        "/api/auth/local", {"username": "sec_changer", "password": PW}, format="json"
    )
    assert old_login.status_code == 401
    new_login = APIClient().post(
        "/api/auth/local", {"username": "sec_changer", "password": "NewPassword-9x"}, format="json"
    )
    assert new_login.status_code == 200


@pytest.mark.django_db
def test_change_password_wrong_old_400(_clean_cache: None) -> None:
    user = _make_user("sec_wrongold", Role.OWNER)
    client = APIClient()
    client.force_authenticate(user)
    resp = client.post(
        "/api/auth/change-password",
        {"old_password": "not-my-password", "new_password": "NewPassword-9x"},
        format="json",
    )
    assert resp.status_code == 400


@pytest.mark.django_db
def test_change_password_too_short_400(_clean_cache: None) -> None:
    user = _make_user("sec_shortpw", Role.OWNER)
    client = APIClient()
    client.force_authenticate(user)
    resp = client.post(
        "/api/auth/change-password",
        {"old_password": PW, "new_password": "short"},
        format="json",
    )
    assert resp.status_code == 400
