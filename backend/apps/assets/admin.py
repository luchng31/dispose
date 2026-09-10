from __future__ import annotations

from django.contrib import admin

from .models import Asset, AssetOwnerMap


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("ip", "hostname", "biz_system", "level", "status", "updated_at")
    list_filter = ("level", "status")
    search_fields = ("ip", "hostname")


@admin.register(AssetOwnerMap)
class AssetOwnerMapAdmin(admin.ModelAdmin):
    list_display = ("id", "ip", "user", "valid_from", "valid_to")
    list_filter = ("valid_from",)
