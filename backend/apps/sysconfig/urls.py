from __future__ import annotations

from django.urls import path

from apps.sysconfig.views import IntegrationListUpdateView, IntegrationTestView

urlpatterns: list[object] = [
    path("ops/integrations", IntegrationListUpdateView.as_view()),
    path("ops/integrations/test", IntegrationTestView.as_view()),
]
