from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.db import IntegrityError
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts import mfa as mfa_lib
from apps.accounts import wecom as wecom_lib
from apps.accounts.models import Role, User
from apps.accounts.serializers import (
    LocalLoginSerializer,
    LogoutSerializer,
    RefreshSerializer,
    TokenResponseSerializer,
    TotpConfirmSerializer,
    TotpDisableSerializer,
    UserInfoSerializer,
    WeComCallbackSerializer,
)

logger = logging.getLogger(__name__)


def _secret() -> str:
    configured: str = str(getattr(settings, "JWT_SECRET_KEY", "") or "")
    if configured:
        return configured
    logger.warning("JWT_SECRET_KEY is empty; falling back to SECRET_KEY. Set JWT_SECRET_KEY in production.")
    return str(settings.SECRET_KEY)


def mint_jwt(user: User) -> str:
    lifetime: timedelta = settings.JWT_ACCESS_TOKEN_LIFETIME
    now: datetime = datetime.now(UTC)
    payload: dict[str, object] = {
        "uid": user.pk,
        "username": user.username,
        "role": user.role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + lifetime).timestamp()),
    }
    return jwt.encode(
        payload, _secret(), algorithm=str(getattr(settings, "JWT_ALGORITHM", "HS256"))
    )


def _pwd_mark(user: User) -> str:
    """Short fingerprint of the current password hash.

    Embedded in refresh tokens so a password change/reset silently invalidates
    outstanding refresh tokens — no DB migration, no token table.
    """
    return hashlib.sha256(str(user.password).encode()).hexdigest()[:16]


def mint_refresh_token(user: User) -> str:
    lifetime: timedelta = settings.JWT_REFRESH_TOKEN_LIFETIME
    now: datetime = datetime.now(UTC)
    payload: dict[str, object] = {
        "uid": user.pk,
        "username": user.username,
        "role": user.role,
        "type": "refresh",
        "jti": uuid.uuid4().hex,
        "pwd_mark": _pwd_mark(user),
        "iat": int(now.timestamp()),
        "exp": int((now + lifetime).timestamp()),
    }
    return jwt.encode(
        payload, _secret(), algorithm=str(getattr(settings, "JWT_ALGORITHM", "HS256"))
    )


def _refresh_denied_key(jti: str) -> str:
    return f"refresh_denied:{jti}"


def _deny_refresh_jti(jti: str, ttl_seconds: int) -> None:
    from django.core.cache import cache

    try:
        cache.set(_refresh_denied_key(jti), 1, max(int(ttl_seconds), 1))
    except Exception:
        pass


def _is_refresh_denied(jti: str) -> bool:
    from django.core.cache import cache

    try:
        return bool(cache.get(_refresh_denied_key(jti)))
    except Exception:
        return False


def _decode_refresh_token(raw: str) -> dict[str, object] | None:
    try:
        payload: dict[str, object] = jwt.decode(
            raw, _secret(), algorithms=[str(getattr(settings, "JWT_ALGORITHM", "HS256"))]
        )
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "refresh":
        return None
    return payload


def issue_token_pair(user: User) -> dict[str, object]:
    return {
        "jwt": mint_jwt(user),
        "refresh_token": mint_refresh_token(user),
        "user": user_payload(user),
    }


def user_payload(user: User) -> dict[str, object]:
    return {
        "id": user.pk,
        "username": user.username,
        "wecom_userid": user.wecom_userid,
        "dept": user.dept,
        "role": user.role,
        "totp_enrolled": bool(user.totp_secret),
    }


class AuthError(Response):
    def __init__(self, detail: str, status_code: int) -> None:
        super().__init__({"detail": detail}, status=status_code)


def _failure_key(username: str) -> str:
    return f"login_fail:{username.lower()}"


def _login_locked(username: str) -> bool:
    from django.conf import settings as dj_settings
    from django.core.cache import cache

    try:
        failures: int = int(cache.get(_failure_key(username), 0) or 0)
    except Exception:
        return False
    return failures >= int(getattr(dj_settings, "LOGIN_MAX_FAILURES", 10))


def _register_login_failure(username: str) -> None:
    from django.conf import settings as dj_settings
    from django.core.cache import cache

    key = _failure_key(username)
    ttl = int(getattr(dj_settings, "LOGIN_LOCKOUT_SECONDS", 900))
    try:
        cache.incr(key)
    except ValueError:
        try:
            cache.set(key, 1, ttl)
        except Exception:
            pass
    except Exception:
        pass


def _clear_login_failures(username: str) -> None:
    from django.core.cache import cache

    try:
        cache.delete(_failure_key(username))
    except Exception:
        pass


class ChangePasswordView(APIView):
    """POST /api/auth/change-password {old_password, new_password} -> {jwt, user}.

    Self-service for temp-password accounts (CSV bulk-create / admin reset);
    returns a fresh JWT so the caller stays logged in.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        user = request.user
        if not isinstance(user, User):
            return AuthError("unauthenticated", status.HTTP_401_UNAUTHORIZED)
        old: str = str(request.data.get("old_password", "") or "")
        new: str = str(request.data.get("new_password", "") or "")
        if not user.check_password(old):
            return AuthError("旧密码错误", status.HTTP_400_BAD_REQUEST)
        if len(new) < 8:
            return AuthError("新密码至少8位", status.HTTP_400_BAD_REQUEST)
        if new == old:
            return AuthError("新密码不能与旧密码相同", status.HTTP_400_BAD_REQUEST)
        user.set_password(new)
        user.save(update_fields=["password"])
        _clear_login_failures(user.username)
        body: dict[str, object] = issue_token_pair(user)
        return Response(TokenResponseSerializer(body).data)


class WeComCallbackView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = WeComCallbackSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        code: str = str(serializer.validated_data["code"])
        try:
            info: wecom_lib.WeComUserInfo = wecom_lib.exchange_code_for_user(code)
        except wecom_lib.WeComNotConfiguredError:
            return AuthError("wecom not configured; use local login", status.HTTP_422_UNPROCESSABLE_ENTITY)
        except wecom_lib.WeComExchangeError:
            return AuthError("invalid wecom code", status.HTTP_401_UNAUTHORIZED)
        user: User | None = User.objects.filter(wecom_userid=info.userid).first()
        if user is None:
            try:
                user = User.objects.create(
                    username=info.userid,
                    wecom_userid=info.userid,
                    dept=info.department,
                    role=Role.OWNER,
                )
            except IntegrityError:
                return AuthError("wecom login conflict", status.HTTP_401_UNAUTHORIZED)
        body: dict[str, object] = issue_token_pair(user)
        out = TokenResponseSerializer(body)
        return Response(out.data, status=status.HTTP_200_OK)


class LocalLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = LocalLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        username: str = str(serializer.validated_data["username"])
        password: str = str(serializer.validated_data["password"])
        totp: str = str(serializer.validated_data.get("totp", "") or "")
        if _login_locked(username):
            return AuthError("失败次数过多，账号已临时锁定，请稍后再试", status.HTTP_429_TOO_MANY_REQUESTS)
        user = authenticate(request, username=username, password=password)
        if not isinstance(user, User):
            _register_login_failure(username)
            return AuthError("invalid credentials", status.HTTP_401_UNAUTHORIZED)
        if user.totp_secret:
            if not totp:
                return AuthError("totp required", status.HTTP_401_UNAUTHORIZED)
            try:
                ok: bool = mfa_lib.verify_code(user.totp_secret, totp)
            except mfa_lib.TotpError:
                return AuthError("totp misconfigured", status.HTTP_401_UNAUTHORIZED)
            if not ok:
                return AuthError("invalid totp", status.HTTP_401_UNAUTHORIZED)
        _clear_login_failures(username)
        body: dict[str, object] = issue_token_pair(user)
        out = TokenResponseSerializer(body)
        return Response(out.data, status=status.HTTP_200_OK)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        user = request.user
        assert isinstance(user, User)
        return Response(UserInfoSerializer(user_payload(user)).data)


class TokenRefreshView(APIView):
    """POST /api/auth/refresh {refresh_token} -> new {jwt, refresh_token, user}.

    Rotation: every refresh token is single-use. A successful call denies the
    presented jti (TTL = its remaining lifetime) and issues a fresh pair, so
    replaying an old refresh token yields 401 (reuse detection). A password
    change alters pwd_mark and silently invalidates outstanding refreshes.
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = RefreshSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        payload: dict[str, object] | None = _decode_refresh_token(
            str(serializer.validated_data["refresh_token"])
        )
        if payload is None:
            return AuthError("invalid refresh token", status.HTTP_401_UNAUTHORIZED)
        uid: object = payload.get("uid")
        jti: object = payload.get("jti")
        if not isinstance(uid, int) or not isinstance(jti, str) or not jti:
            return AuthError("invalid refresh token", status.HTTP_401_UNAUTHORIZED)
        if _is_refresh_denied(jti):
            return AuthError("refresh token already used", status.HTTP_401_UNAUTHORIZED)
        user: User | None = User.objects.filter(pk=uid, is_active=True).first()
        if user is None:
            return AuthError("invalid refresh token", status.HTTP_401_UNAUTHORIZED)
        if not hmac.compare_digest(str(payload.get("pwd_mark", "")), _pwd_mark(user)):
            return AuthError("refresh token expired", status.HTTP_401_UNAUTHORIZED)
        exp: object = payload.get("exp")
        ttl: int = int(exp) - int(datetime.now(UTC).timestamp()) if isinstance(exp, int) else 0
        if ttl <= 0:
            return AuthError("refresh token expired", status.HTTP_401_UNAUTHORIZED)
        _deny_refresh_jti(jti, ttl)
        return Response(TokenResponseSerializer(issue_token_pair(user)).data)


class LogoutView(APIView):
    """POST /api/auth/logout [{refresh_token}] -> {logged_out: true}.

    Revokes the presented refresh token (rotation blacklist); the access
    token simply expires. Always 200 — logout must never fail the client.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = LogoutSerializer(data=request.data)
        if serializer.is_valid():
            raw: str = str(serializer.validated_data.get("refresh_token", "") or "")
            if raw:
                payload: dict[str, object] | None = _decode_refresh_token(raw)
                if payload is not None:
                    jti: object = payload.get("jti")
                    exp: object = payload.get("exp")
                    if isinstance(jti, str) and jti and isinstance(exp, int):
                        ttl: int = exp - int(datetime.now(UTC).timestamp())
                        _deny_refresh_jti(jti, ttl)
        return Response({"logged_out": True})


TOTP_ISSUER: str = "VulnTicket"


def _otpauth_url(username: str, secret: str) -> str:
    label: str = f"{TOTP_ISSUER}:{username}"
    return (
        f"otpauth://totp/{quote(label)}"
        f"?secret={secret}&issuer={quote(TOTP_ISSUER)}&digits=6&period=30"
    )


class TotpSetupView(APIView):
    """POST /api/auth/totp/setup -> {secret, otpauth_url} (self-service enroll).

    Stateless: the secret is NOT saved here. The caller binds it in an
    authenticator app (manual entry; no QR lib by zero-new-deps policy) and
    activates it via POST /api/auth/totp/confirm. Already enrolled -> 400.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        user = request.user
        if not isinstance(user, User):
            return AuthError("unauthenticated", status.HTTP_401_UNAUTHORIZED)
        if user.totp_secret:
            return AuthError("totp already enrolled; disable first", status.HTTP_400_BAD_REQUEST)
        secret: str = mfa_lib.generate_secret()
        return Response({"secret": secret, "otpauth_url": _otpauth_url(user.username, secret)})


class TotpConfirmView(APIView):
    """POST /api/auth/totp/confirm {secret, code} -> {enrolled: true}.

    Verifies the code against the setup secret and only then persists it,
    so a mistyped secret can never lock the account.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        user = request.user
        if not isinstance(user, User):
            return AuthError("unauthenticated", status.HTTP_401_UNAUTHORIZED)
        if user.totp_secret:
            return AuthError("totp already enrolled; disable first", status.HTTP_400_BAD_REQUEST)
        serializer = TotpConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        secret: str = str(serializer.validated_data["secret"])
        code: str = str(serializer.validated_data["code"])
        try:
            ok: bool = mfa_lib.verify_code(secret, code)
        except mfa_lib.TotpError:
            return AuthError("invalid totp secret", status.HTTP_400_BAD_REQUEST)
        if not ok:
            return AuthError("invalid totp", status.HTTP_401_UNAUTHORIZED)
        user.totp_secret = secret
        user.save(update_fields=["totp_secret"])
        return Response({"enrolled": True})


class TotpDisableView(APIView):
    """POST /api/auth/totp/disable {password} -> {enrolled: false} (lost phone path)."""

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        user = request.user
        if not isinstance(user, User):
            return AuthError("unauthenticated", status.HTTP_401_UNAUTHORIZED)
        if not user.totp_secret:
            return AuthError("totp not enrolled", status.HTTP_400_BAD_REQUEST)
        serializer = TotpDisableSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not user.check_password(str(serializer.validated_data["password"] or "")):
            return AuthError("密码错误", status.HTTP_400_BAD_REQUEST)
        user.totp_secret = ""
        user.save(update_fields=["totp_secret"])
        return Response({"enrolled": False})
