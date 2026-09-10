from __future__ import annotations

from django.contrib import admin

from .models import ScanBatch


@admin.register(ScanBatch)
class ScanBatchAdmin(admin.ModelAdmin):
    list_display = ("id", "file_name", "file_hash", "source", "created_at")
    list_filter = ("source",)
    search_fields = ("file_name", "file_hash")
