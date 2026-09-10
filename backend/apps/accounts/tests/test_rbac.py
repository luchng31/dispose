from __future__ import annotations

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts import mfa as mfa_lib
from apps.accounts.models import Role, User
from apps.accounts.permissions import (
    IsAuditorReadOnly,
    IsOperator,
    IsOwnerScoped,
    can_approve_delay,
    can_close,
    get_visible_tickets,
)
from apps.assets.models import Asset, AssetOwnerMap
from apps.tickets.models import Severity, VulnTicket


def _make_user(
    username: str, role: str, password: str = "pw-test-only-123", **kwargs: object
) -> User:
    params: dict[str, object] = {
        "username": username,
        "password": password,
        "wecom_userid": username,
        "role": role,
    }
    params.update(kwargs)
    user: User = User.objects.create_user(**params)  # type: ignore[arg-type]
    return user


@pytest.mark.django_db
def test_local_login_returns_jwt() -> None:
    _make_user("op_local", Role.OPERATOR)
    client = APIClient()
    resp = client.post(
        "/api/auth/local",
        {"username": "op_local", "password": "pw-test-only-123"},
        format="json",
    )
    assert resp.status_code == 200
    assert "jwt" in resp.data
    assert resp.data["user"]["role"] == Role.OPERATOR


@pytest.mark.django_db
def test_local_login_wrong_password_401() -> None:
    _make_user("op_bad", Role.OPERATOR)
    client = APIClient()
    resp = client.post(
        "/api/auth/local",
        {"username": "op_bad", "password": "wrong"},
        format="json",
    )
    assert resp.status_code == 401


@pytest.mark.django_db
def test_totp_wrong_code_401() -> None:
    secret: str = mfa_lib.generate_secret()
    _make_user("mfa_user", Role.OWNER, totp_secret=secret)
    client = APIClient()
    resp = client.post(
        "/api/auth/local",
        {"username": "mfa_user", "password": "pw-test-only-123", "totp": "000000"},
        format="json",
    )
    assert resp.status_code == 401


@pytest.mark.django_db
def test_totp_correct_code_200() -> None:
    secret: str = mfa_lib.generate_secret()
    _make_user("mfa_ok", Role.OWNER, totp_secret=secret)
    client = APIClient()
    resp = client.post(
        "/api/auth/local",
        {
            "username": "mfa_ok",
            "password": "pw-test-only-123",
            "totp": mfa_lib.current_code(secret),
        },
        format="json",
    )
    assert resp.status_code == 200
    assert "jwt" in resp.data


@pytest.mark.django_db
def test_totp_required_when_enrolled_401() -> None:
    _make_user("mfa_req", Role.OWNER, totp_secret=mfa_lib.generate_secret())
    client = APIClient()
    resp = client.post(
        "/api/auth/local",
        {"username": "mfa_req", "password": "pw-test-only-123"},
        format="json",
    )
    assert resp.status_code == 401


@pytest.mark.django_db
def test_wecom_callback_without_env_falls_back_422() -> None:
    client = APIClient()
    resp = client.post("/api/auth/wecom/callback", {"code": "abc"}, format="json")
    assert resp.status_code == 422
    assert "local" in resp.data["detail"]


@pytest.mark.django_db
def test_owner_isolation_cross_owner_excluded() -> None:
    owner_a: User = _make_user("owner_a", Role.OWNER)
    owner_b: User = _make_user("owner_b", Role.OWNER)
    Asset.objects.create(ip="10.0.0.1")
    Asset.objects.create(ip="10.0.0.2")
    now = timezone.now()
    AssetOwnerMap.objects.create(ip_id="10.0.0.1", user=owner_a, valid_from=now)
    AssetOwnerMap.objects.create(ip_id="10.0.0.2", user=owner_b, valid_from=now)
    VulnTicket.objects.create(
        dedup_key="a" * 32, ip="10.0.0.1", port=80, severity=Severity.HIGH
    )
    VulnTicket.objects.create(
        dedup_key="b" * 32, ip="10.0.0.2", port=80, severity=Severity.HIGH
    )
    visible_a = get_visible_tickets(owner_a)
    assert {t.ip for t in visible_a} == {"10.0.0.1"}
    visible_b = get_visible_tickets(owner_b)
    assert {t.ip for t in visible_b} == {"10.0.0.2"}


@pytest.mark.django_db
def test_operator_sees_all_tickets() -> None:
    op: User = _make_user("op_all", Role.OPERATOR)
    VulnTicket.objects.create(
        dedup_key="c" * 32, ip="10.0.1.1", port=443, severity=Severity.LOW
    )
    assert get_visible_tickets(op).count() >= 1


@pytest.mark.django_db
def test_non_operator_close_attempt_403_at_permission_level() -> None:
    from rest_framework.test import APIRequestFactory

    factory = APIRequestFactory()
    owner: User = _make_user("owner_close", Role.OWNER)
    request = factory.post("/ops/vulns/1/close")
    request.user = owner
    assert IsOperator().has_permission(request, None) is False  # type: ignore[arg-type]


@pytest.mark.django_db
def test_only_operator_can_close() -> None:
    op: User = _make_user("op_close", Role.OPERATOR)
    owner: User = _make_user("owner_noclose", Role.OWNER)
    auditor: User = _make_user("aud_noclose", Role.AUDITOR)
    leader: User = _make_user("lead_noclose", Role.LEADER)
    assert can_close(op) is True
    assert can_close(owner) is False
    assert can_close(auditor) is False
    assert can_close(leader) is False


@pytest.mark.django_db
def test_leader_can_approve_delay_owner_cannot() -> None:
    leader: User = _make_user("lead_delay", Role.LEADER)
    owner: User = _make_user("owner_delay", Role.OWNER)
    assert can_approve_delay(leader) is True
    assert can_approve_delay(owner) is False


@pytest.mark.django_db
def test_auditor_read_only() -> None:
    from rest_framework.test import APIRequestFactory

    factory = APIRequestFactory()
    auditor: User = _make_user("aud_ro", Role.AUDITOR)
    get_req = factory.get("/api/x")
    get_req.user = auditor
    post_req = factory.post("/api/x")
    post_req.user = auditor
    perm = IsAuditorReadOnly()
    assert perm.has_permission(get_req, None) is True  # type: ignore[arg-type]
    assert perm.has_permission(post_req, None) is False  # type: ignore[arg-type]


@pytest.mark.django_db
def test_owner_object_level_403_cross_owner() -> None:
    from rest_framework.test import APIRequestFactory

    factory = APIRequestFactory()
    owner_a: User = _make_user("owner_obj_a", Role.OWNER)
    Asset.objects.create(ip="10.0.2.1")
    AssetOwnerMap.objects.create(
        ip_id="10.0.2.1", user=owner_a, valid_from=timezone.now()
    )
    other = VulnTicket.objects.create(
        dedup_key="d" * 32, ip="10.9.9.9", port=22, severity=Severity.MEDIUM
    )
    own = VulnTicket.objects.create(
        dedup_key="e" * 32, ip="10.0.2.1", port=22, severity=Severity.MEDIUM
    )
    perm = IsOwnerScoped()
    request = factory.get("/api/x")
    request.user = owner_a
    assert perm.has_object_permission(request, None, other) is False  # type: ignore[arg-type]
    assert perm.has_object_permission(request, None, own) is True  # type: ignore[arg-type]


@pytest.mark.django_db
def test_jwt_authenticates_me_endpoint() -> None:
    _make_user("me_user", Role.OWNER)
    client = APIClient()
    login = client.post(
        "/api/auth/local",
        {"username": "me_user", "password": "pw-test-only-123"},
        format="json",
    )
    token: str = str(login.data["jwt"])
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.data["username"] == "me_user"
