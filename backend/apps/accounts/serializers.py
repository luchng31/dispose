from __future__ import annotations

from rest_framework import serializers


class WeComCallbackSerializer(serializers.Serializer):
    code: str = serializers.CharField(max_length=256)

    def validate_code(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError("code must not be empty")
        return value


class LocalLoginSerializer(serializers.Serializer):
    username: str = serializers.CharField(max_length=150)
    password: str = serializers.CharField(max_length=256, write_only=True)
    totp: str = serializers.CharField(
        max_length=8, required=False, allow_blank=True, default=""
    )


class UserInfoSerializer(serializers.Serializer):
    id: int = serializers.IntegerField()
    username: str = serializers.CharField()
    wecom_userid: str = serializers.CharField()
    dept: str = serializers.CharField()
    role: str = serializers.CharField()
    totp_enrolled: bool = serializers.BooleanField(required=False, default=False)


class TokenResponseSerializer(serializers.Serializer):
    jwt: str = serializers.CharField()
    refresh_token: str = serializers.CharField()
    user: UserInfoSerializer = UserInfoSerializer()


class TotpConfirmSerializer(serializers.Serializer):
    secret: str = serializers.CharField(max_length=64)
    code: str = serializers.CharField(max_length=8)

    def validate_secret(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError("secret must not be empty")
        return value.strip()

    def validate_code(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError("code must not be empty")
        return value.strip()


class TotpDisableSerializer(serializers.Serializer):
    password: str = serializers.CharField(max_length=256, write_only=True)


class RefreshSerializer(serializers.Serializer):
    refresh_token: str = serializers.CharField()

    def validate_refresh_token(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError("refresh_token must not be empty")
        return value.strip()


class LogoutSerializer(serializers.Serializer):
    refresh_token: str = serializers.CharField(
        max_length=4096, required=False, allow_blank=True, default=""
    )
