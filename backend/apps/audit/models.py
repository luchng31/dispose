from __future__ import annotations

from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    """Append-only. No update/delete API ever (enforced in Wave2 Task2)."""

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="audit_logs",
    )
    action: str = models.CharField(max_length=64)
    ticket = models.ForeignKey(
        "tickets.VulnTicket", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="audit_logs",
    )
    entity: str = models.CharField(max_length=64, blank=True, default="")
    entity_id: str = models.CharField(max_length=128, blank=True, default="")
    diff_json = models.JSONField(default=dict, blank=True)
    ip_addr: str = models.CharField(max_length=45, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "audit_log"
        verbose_name = "审计日志"
        verbose_name_plural = "审计日志"
        indexes = [
            models.Index(fields=["ticket", "created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.action}#{self.id}"
