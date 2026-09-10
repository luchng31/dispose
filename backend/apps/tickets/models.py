from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class Severity(models.TextChoices):
    CRITICAL = "严重", "严重"
    HIGH = "高", "高"
    MEDIUM = "中", "中"
    LOW = "低", "低"


class TicketState(models.TextChoices):
    PENDING_ASSIGN = "待分配", "待分配"
    PENDING_FIX = "待修复", "待修复"
    PENDING_RETEST = "待复测", "待复测"
    CLOSED = "已闭合", "已闭合"
    DELAYED = "已延期", "已延期"
    IGNORED = "已忽略", "已忽略"


class Protocol(models.TextChoices):
    TCP = "tcp", "TCP"
    UDP = "udp", "UDP"


class VulnTicket(models.Model):
    dedup_key: str = models.CharField(max_length=32, unique=True, db_index=True)
    ip: str = models.CharField(max_length=45, db_index=True)
    port: int = models.IntegerField()
    protocol: str = models.CharField(
        max_length=8, choices=Protocol.choices, default=Protocol.TCP
    )
    service: str = models.CharField(max_length=128, blank=True, default="")
    plugin_id: str = models.CharField(max_length=64, blank=True, default="")
    plugin_name: str = models.CharField(max_length=512, blank=True, default="")
    cve: str = models.CharField(max_length=64, blank=True, default="")
    severity: str = models.CharField(max_length=8, choices=Severity.choices)
    cvss = models.FloatField(null=True, blank=True)
    description: str = models.TextField(blank=True, default="")
    solution: str = models.TextField(blank=True, default="")
    asset = models.ForeignKey(
        "assets.Asset", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="tickets",
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="tickets",
    )
    state: str = models.CharField(
        max_length=16, choices=TicketState.choices, default=TicketState.PENDING_ASSIGN
    )
    sla_due_at: models.DateTimeField = models.DateTimeField(null=True, blank=True)
    first_seen_at: models.DateTimeField = models.DateTimeField(null=True, blank=True)
    last_seen_at: models.DateTimeField = models.DateTimeField(null=True, blank=True)
    fix_evidence = models.JSONField(default=dict, blank=True)
    delay_until: models.DateTimeField = models.DateTimeField(null=True, blank=True)
    ignore_reason: str = models.TextField(blank=True, default="")
    batch = models.ForeignKey(
        "imports.ScanBatch", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="tickets",
    )
    created_at: models.DateTimeField = models.DateTimeField(auto_now_add=True)
    updated_at: models.DateTimeField = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "vuln_ticket"
        verbose_name = "漏洞工单"
        verbose_name_plural = "漏洞工单"
        indexes = [
            models.Index(fields=["ip", "state"]),
            models.Index(fields=["assignee", "state"]),
            models.Index(fields=["sla_due_at"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["state", "severity"]),
            models.Index(fields=["-updated_at"]),
        ]

    def __str__(self) -> str:
        return str(self.dedup_key)


def attachment_upload_to(instance: object, filename: str) -> str:
    base = str(filename or "").replace("\\", "/").rsplit("/", 1)[-1] or "file"
    stamp = timezone.now().strftime("%Y/%m")
    return f"ticket_attachments/{stamp}/{uuid.uuid4().hex}_{base}"


class TicketAttachment(models.Model):
    ticket = models.ForeignKey(
        VulnTicket, on_delete=models.CASCADE, related_name="attachments",
    )
    file = models.FileField(upload_to=attachment_upload_to)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="uploaded_attachments",
    )
    created_at: models.DateTimeField = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ticket_attachment"
        verbose_name = "工单附件"
        verbose_name_plural = "工单附件"

    def __str__(self) -> str:
        return f"{self.ticket_id}/{self.pk}"


class DelayRequestStatus(models.TextChoices):
    PENDING = "待审批", "待审批"
    APPROVED = "已批准", "已批准"
    REJECTED = "已驳回", "已驳回"


class DelayRequest(models.Model):
    ticket = models.ForeignKey(
        VulnTicket, on_delete=models.CASCADE, related_name="delay_requests",
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="delay_requests",
    )
    delay_days = models.IntegerField(null=True, blank=True)
    delay_until = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True, default="")
    status: str = models.CharField(
        max_length=16, choices=DelayRequestStatus.choices,
        default=DelayRequestStatus.PENDING,
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="decided_delays",
    )
    decided_at: models.DateTimeField = models.DateTimeField(null=True, blank=True)
    decide_note = models.TextField(blank=True, default="")
    created_at: models.DateTimeField = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "delay_request"
        verbose_name = "延期申请"
        verbose_name_plural = "延期申请"

    def __str__(self) -> str:
        return f"{self.ticket_id}/{self.status}"


class SlaPolicy(models.Model):
    severity: str = models.CharField(
        max_length=8, choices=Severity.choices, primary_key=True
    )
    days: int = models.IntegerField()
    warn_days_before: int = models.IntegerField(default=3)

    class Meta:
        db_table = "sla_policy"
        verbose_name = "SLA策略"
        verbose_name_plural = "SLA策略"

    def __str__(self) -> str:
        return f"{self.severity}:{self.days}天"
