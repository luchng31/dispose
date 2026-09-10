from __future__ import annotations

from django.contrib import admin

from .models import DelayRequest, SlaPolicy, TicketAttachment, VulnTicket


@admin.register(VulnTicket)
class VulnTicketAdmin(admin.ModelAdmin):
    list_display = ("id", "dedup_key", "ip", "port", "severity", "state", "assignee")
    list_filter = ("severity", "state")
    search_fields = ("dedup_key", "ip", "cve", "plugin_id")


@admin.register(SlaPolicy)
class SlaPolicyAdmin(admin.ModelAdmin):
    list_display = ("severity", "days", "warn_days_before")


@admin.register(TicketAttachment)
class TicketAttachmentAdmin(admin.ModelAdmin):
    list_display = ("id", "ticket", "uploaded_by", "created_at")
    readonly_fields = ("created_at",)


@admin.register(DelayRequest)
class DelayRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "ticket", "requested_by", "status", "created_at")
    list_filter = ("status",)
