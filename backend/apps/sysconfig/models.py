from __future__ import annotations

from django.db import models


class IntegrationSetting(models.Model):
    """Single DB-backed integration knob (page-editable, no restart).

    Precedence (see apps.sysconfig.store): non-empty DB row wins, else the
    mapped os.environ fallback, else the caller-supplied default.
    Secrets are stored as plain text rows; they are NEVER serialized back
    by the API (views mask them) nor written into audit details.
    """

    key: str = models.CharField(max_length=64, unique=True)
    value: str = models.TextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "integration_setting"
        verbose_name = "集成配置"
        verbose_name_plural = "集成配置"

    def __str__(self) -> str:
        return str(self.key)
