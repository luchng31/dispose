from __future__ import annotations

from django.urls import path

from apps.notify.views import NotifyStatusView, NotifyTestView

urlpatterns: list[object] = [
    path("ops/notify/status", NotifyStatusView.as_view()),
    path("ops/notify/test", NotifyTestView.as_view()),
]
