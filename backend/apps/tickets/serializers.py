"""Task6 serializers: stable response shapes for the frontend lane (Task7/Task8).

List shape (stable contract): {id, ip, port, title, severity, state,
sla_due_at, assignee, reopen_count, first_seen_at, source} where ``title``
falls back plugin_name -> cve -> "ip:port", ``assignee`` is the username
(null when unassigned), ``reopen_count`` reads fix_evidence JSON (frozen
schema), ``first_seen_at`` is the RSAS first-seen datetime (nullable), and
``source`` is the ScanBatch source display label (漏洞扫描=FTP投递/手工上传名, null
when the ticket has no batch).

Detail shape: every list field plus the full model fields, fix_evidence,
and a read-only ``timeline`` of audit rows (oldest first).
"""

from __future__ import annotations

from typing import Any

from rest_framework import serializers

from apps.audit.models import AuditLog
from apps.tickets.models import DelayRequest, TicketAttachment, VulnTicket


def ticket_title(ticket: VulnTicket) -> str:
    """Human title without a schema change: plugin_name > cve > ip:port."""
    if ticket.plugin_name:
        return str(ticket.plugin_name)
    if ticket.cve:
        return str(ticket.cve)
    return f"{ticket.ip}:{ticket.port}"


def ticket_reopen_count(ticket: VulnTicket) -> int:
    """reopen_count lives in fix_evidence JSON (Task1 schema frozen)."""
    evidence: Any = ticket.fix_evidence or {}
    if not isinstance(evidence, dict):
        return 0
    try:
        return int(evidence.get("reopen_count", 0))
    except (TypeError, ValueError):
        return 0


def assignee_name(ticket: VulnTicket) -> str | None:
    user = ticket.assignee
    return str(user.username) if user is not None else None


def source_label(ticket: VulnTicket) -> str | None:
    """List/CSV 来源标签：手工批次显示批次名（可手填），扫描批次显示渠道."""
    from apps.imports.models import BatchSource

    batch = ticket.batch
    if batch is None:
        return None
    if batch.source == BatchSource.MANUAL and batch.file_name:
        return str(batch.file_name)
    return str(batch.get_source_display())


class VulnTicketListSerializer(serializers.ModelSerializer):
    """GET /api/tickets/my + /api/ops/pool row shape."""

    title = serializers.SerializerMethodField()
    assignee = serializers.SerializerMethodField()
    reopen_count = serializers.SerializerMethodField()
    source = serializers.SerializerMethodField()

    class Meta:
        model = VulnTicket
        fields = [
            "id", "ip", "port", "title", "severity", "state",
            "sla_due_at", "assignee", "reopen_count", "first_seen_at",
            "source",
        ]

    def get_title(self, obj: VulnTicket) -> str:
        return ticket_title(obj)

    def get_assignee(self, obj: VulnTicket) -> str | None:
        return assignee_name(obj)

    def get_reopen_count(self, obj: VulnTicket) -> int:
        return ticket_reopen_count(obj)

    def get_source(self, obj: VulnTicket) -> str | None:
        return source_label(obj)


class AuditTimelineSerializer(serializers.ModelSerializer):
    """Embedded read-only audit row for the detail timeline."""

    actor = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ["id", "action", "actor", "created_at", "diff_json"]

    def get_actor(self, obj: AuditLog) -> str | None:
        user = obj.actor
        return str(user.username) if user is not None else None


class AttachmentSerializer(serializers.ModelSerializer):
    """Read-only attachment row: {id, url, name, uploaded_by, created_at}."""

    url = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    uploaded_by = serializers.SerializerMethodField()

    class Meta:
        model = TicketAttachment
        fields = ["id", "url", "name", "uploaded_by", "created_at"]

    def get_url(self, obj: TicketAttachment) -> str | None:
        if not obj.file:
            return None
        try:
            url = str(obj.file.url)
        except ValueError:
            return None
        request = self.context.get("request")
        if request is not None:
            return str(request.build_absolute_uri(url))
        return url

    def get_name(self, obj: TicketAttachment) -> str:
        base = str(obj.file.name).rsplit("/", 1)[-1] if obj.file else ""
        head, sep, rest = base.partition("_")
        if sep and len(head) == 32 and all(c in "0123456789abcdefABCDEF" for c in head):
            return rest or base
        return base

    def get_uploaded_by(self, obj: TicketAttachment) -> str | None:
        user = obj.uploaded_by
        return str(user.username) if user is not None else None


class VulnTicketDetailSerializer(VulnTicketListSerializer):
    """GET /api/tickets/:id shape: all fields + evidence + timeline."""

    asset = serializers.SerializerMethodField()
    timeline = serializers.SerializerMethodField()
    attachments = serializers.SerializerMethodField()

    class Meta(VulnTicketListSerializer.Meta):
        fields = VulnTicketListSerializer.Meta.fields + [
            "protocol", "service", "plugin_id", "plugin_name", "cve", "cvss",
            "description", "solution", "asset", "first_seen_at", "last_seen_at",
            "fix_evidence", "delay_until", "ignore_reason", "batch",
            "created_at", "updated_at", "timeline", "attachments",
        ]

    def get_asset(self, obj: VulnTicket) -> str | None:
        return str(obj.asset_id) if obj.asset_id else None

    def get_timeline(self, obj: VulnTicket) -> list[dict[str, Any]]:
        rows = getattr(obj, "prefetched_timeline", None)
        if rows is None:
            rows = obj.audit_logs.order_by("created_at", "id")
        return AuditTimelineSerializer(rows, many=True).data

    def get_attachments(self, obj: VulnTicket) -> list[dict[str, Any]]:
        rows = getattr(obj, "prefetched_attachments", None)
        if rows is None:
            rows = obj.attachments.order_by("created_at", "id")
        return AttachmentSerializer(rows, many=True, context=self.context).data


class AuditLogSerializer(serializers.ModelSerializer):
    """GET /api/audit row shape."""

    actor = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = [
            "id", "action", "actor", "ticket_id", "entity", "entity_id",
            "diff_json", "created_at",
        ]

    def get_actor(self, obj: AuditLog) -> str | None:
        user = obj.actor
        return str(user.username) if user is not None else None


class SubmitInputSerializer(serializers.Serializer):
    evidence = serializers.JSONField(required=False, default=dict)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        evidence: Any = attrs.get("evidence", {})
        if not isinstance(evidence, dict):
            raise serializers.ValidationError({"evidence": "evidence 需为对象"})
        return attrs


class DelayInputSerializer(serializers.Serializer):
    delay_days = serializers.IntegerField(required=False, min_value=0)
    delay_until = serializers.DateTimeField(required=False)
    reason = serializers.CharField(required=False, allow_blank=True, default="")
    co_approved_by = serializers.CharField(required=False, allow_blank=True, default="")

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if attrs.get("delay_days") is None and attrs.get("delay_until") is None:
            raise serializers.ValidationError("延期需提供 delay_days 或 delay_until")
        return attrs


class NoteInputSerializer(serializers.Serializer):
    note = serializers.CharField(required=False, allow_blank=True, default="")


class DelayRequestSerializer(serializers.ModelSerializer):
    """延期申请行：申请人/审批人展示用户名。"""

    requested_by = serializers.SerializerMethodField()
    decided_by = serializers.SerializerMethodField()
    ticket_ip = serializers.SerializerMethodField()
    ticket_title = serializers.SerializerMethodField()

    class Meta:
        model = DelayRequest
        fields = [
            "id", "ticket", "ticket_ip", "ticket_title", "requested_by",
            "delay_days", "delay_until", "reason", "status",
            "decided_by", "decided_at", "decide_note", "created_at",
        ]

    def get_requested_by(self, obj: DelayRequest) -> str | None:
        user = obj.requested_by
        return str(user.username) if user is not None else None

    def get_decided_by(self, obj: DelayRequest) -> str | None:
        user = obj.decided_by
        return str(user.username) if user is not None else None

    def get_ticket_ip(self, obj: DelayRequest) -> str:
        return str(obj.ticket.ip)

    def get_ticket_title(self, obj: DelayRequest) -> str:
        return ticket_title(obj.ticket)


class IgnoreInputSerializer(serializers.Serializer):
    reason = serializers.CharField(required=True, allow_blank=False)
    expires_at = serializers.DateTimeField(required=False)
