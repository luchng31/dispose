from __future__ import annotations

from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from apps.accounts.views import (
    ChangePasswordView,
    LocalLoginView,
    LogoutView,
    MeView,
    TokenRefreshView,
    TotpConfirmView,
    TotpDisableView,
    TotpSetupView,
    WeComCallbackView,
)
from apps.assets.views import AssetCreateView, AssetMappingView, AssetOverviewView, AssetRemapView, OrphanAssetView
from apps.cmdb.views import CmdbSyncView

urlpatterns: list[object] = [
    path("admin/", admin.site.urls),
    path("api/auth/wecom/callback", WeComCallbackView.as_view()),
    path("api/auth/local", LocalLoginView.as_view()),
    path("api/auth/refresh", TokenRefreshView.as_view()),
    path("api/auth/logout", LogoutView.as_view()),
    path("api/auth/me", MeView.as_view()),
    path("api/auth/change-password", ChangePasswordView.as_view()),
    path("api/auth/totp/setup", TotpSetupView.as_view()),
    path("api/auth/totp/confirm", TotpConfirmView.as_view()),
    path("api/auth/totp/disable", TotpDisableView.as_view()),
    path("api/imports/", include("apps.imports.urls")),
    path("api/cmdb/sync", CmdbSyncView.as_view()),
    path("api/assets/mapping", AssetMappingView.as_view()),
    path("api/assets/overview", AssetOverviewView.as_view()),
    path("api/assets/orphans", OrphanAssetView.as_view()),
    path("api/assets", AssetCreateView.as_view()),
    path("api/assets/remap", AssetRemapView.as_view()),
    path("api/", include("apps.tickets.urls")),
    path("api/", include("apps.notify.urls")),
    path("api/", include("apps.sysconfig.urls")),
]

if settings.DEBUG or getattr(settings, "SERVE_MEDIA", False):
    from django.urls import re_path
    from django.views.static import serve as media_serve

    urlpatterns += [
        re_path(
            r"^media/(?P<path>.*)$",
            media_serve,
            {"document_root": settings.MEDIA_ROOT},
        )
    ]
