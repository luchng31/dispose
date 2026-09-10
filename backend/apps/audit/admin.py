from __future__ import annotations

from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("id", "actor", "action", "ticket", "entity", "created_at")
    list_filter = ("action",)
    search_fields = ("action", "entity")
    readonly_fields = ("actor", "action", "ticket", "entity", "entity_id",
                       "diff_json", "ip_addr", "created_at")

    def has_add_permission(self, request: object) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object = None) -> bool:
        return False
