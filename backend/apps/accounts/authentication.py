from __future__ import annotations

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.http import HttpRequest
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from apps.accounts.models import User


def _secret() -> str:
    configured: str = str(getattr(settings, "JWT_SECRET_KEY", "") or "")
    if configured:
        return configured
    return str(settings.SECRET_KEY)


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request: Request) -> tuple[User, str] | None:
        header: str = request.headers.get("Authorization", "")
        if not header:
            return None
        scheme: str
        token: str
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        algorithm: str = str(getattr(settings, "JWT_ALGORITHM", "HS256"))
        try:
            payload: dict[str, object] = jwt.decode(
                token.strip(), _secret(), algorithms=[algorithm]
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationFailed("token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationFailed("invalid token") from exc
        user_id: object = payload.get("uid")
        if not isinstance(user_id, int):
            raise AuthenticationFailed("invalid token")
        if str(payload.get("type", "access")) != "access":
            raise AuthenticationFailed("invalid token")
        user_model = get_user_model()
        try:
            user: User = user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist as exc:
            raise AuthenticationFailed("unknown user") from exc
        if not user.is_active:
            raise AuthenticationFailed("user disabled")
        return (user, token.strip())


class WeComBackend(ModelBackend):
    def authenticate(
        self,
        request: HttpRequest | None,
        username: str | None = None,
        password: str | None = None,
        **kwargs: object,
    ) -> AbstractBaseUser | None:
        if not username or not password:
            return None
        user_model = get_user_model()
        try:
            user: AbstractBaseUser | None = user_model.objects.get(username=username)
        except user_model.DoesNotExist:
            return None
        if user is not None and user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
