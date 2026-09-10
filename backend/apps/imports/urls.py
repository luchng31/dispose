from __future__ import annotations

from django.urls import path

from .views import (
    AssetImportView,
    AssetTemplateView,
    BatchListView,
    FieldMapView,
    OwnerEmailImportView,
    OwnerEmailTemplateView,
    RsasImportView,
)

urlpatterns = [
    path("rsas", RsasImportView.as_view(), name="rsas-import"),
    path("batches", BatchListView.as_view(), name="import-batches"),
    path("assets", AssetImportView.as_view(), name="asset-import"),
    path("assets/template", AssetTemplateView.as_view(), name="asset-template"),
    path("owner-emails", OwnerEmailImportView.as_view(), name="owner-email-import"),
    path("owner-emails/template", OwnerEmailTemplateView.as_view(), name="owner-email-template"),
    path("field-map", FieldMapView.as_view(), name="field-map"),
]
