from __future__ import annotations

from django.conf import settings
from django.db import models


class BatchSource(models.TextChoices):
    FTP = "ftp", "FTP投递"
    MANUAL = "manual", "手工上传"


class ScanBatch(models.Model):
    file_name: str = models.CharField(max_length=512)
    file_hash: str = models.CharField(max_length=64, unique=True)
    source: str = models.CharField(
        max_length=16, choices=BatchSource.choices, default=BatchSource.FTP
    )
    rsas_version: str = models.CharField(max_length=64, blank=True, default="")
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="scan_batches",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    stats_json = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "scan_batch"
        verbose_name = "扫描批次"
        verbose_name_plural = "扫描批次"

    def __str__(self) -> str:
        return f"{self.file_name}({self.file_hash[:8]})"
