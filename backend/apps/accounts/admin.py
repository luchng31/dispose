from __future__ import annotations

from django.contrib import admin

from .models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "wecom_userid", "username", "dept", "role")
    list_filter = ("role",)
    search_fields = ("wecom_userid", "username")
