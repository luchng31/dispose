from __future__ import annotations

from django.conf import settings
from django.db import models


class AssetLevel(models.TextChoices):
    CRITICAL = "critical", "核心"
    HIGH = "high", "重要"
    MEDIUM = "medium", "一般"
    LOW = "low", "低"


class AssetStatus(models.TextChoices):
    ONLINE = "online", "在线"
    OFFLINE = "offline", "下线"
    UNKNOWN = "unknown", "未知"


class Asset(models.Model):
    ip: str = models.CharField(max_length=45, primary_key=True)
    hostname: str = models.CharField(max_length=255, blank=True, default="")
    os: str = models.CharField(max_length=255, blank=True, default="")
    biz_system: str = models.CharField(max_length=255, blank=True, default="")
    level: str = models.CharField(
        max_length=16, choices=AssetLevel.choices, default=AssetLevel.MEDIUM
    )
    status: str = models.CharField(
        max_length=16, choices=AssetStatus.choices, default=AssetStatus.UNKNOWN
    )
    updated_at: models.DateTimeField = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "asset"
        verbose_name = "资产"
        verbose_name_plural = "资产"

    def __str__(self) -> str:
        return str(self.ip)


class AssetOwnerMap(models.Model):
    ip: Asset = models.ForeignKey(
        Asset, on_delete=models.CASCADE, related_name="owner_history", db_column="ip"
    )
    user: settings.AUTH_USER_MODEL = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="asset_maps"
    )
    valid_from: models.DateTimeField = models.DateTimeField()
    valid_to: models.DateTimeField = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "asset_owner_map"
        verbose_name = "资产负责人映射"
        verbose_name_plural = "资产负责人映射"
        indexes = [
            models.Index(fields=["valid_to"]),
        ]

    def __str__(self) -> str:
        return f"{self.ip_id} -> {self.user_id}"
