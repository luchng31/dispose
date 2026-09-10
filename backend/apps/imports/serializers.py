from __future__ import annotations

from typing import Any

from rest_framework import serializers

from .models import ScanBatch


class ScanBatchSerializer(serializers.ModelSerializer):
    stats = serializers.SerializerMethodField()

    class Meta:
        model = ScanBatch
        fields = (
            "id", "file_name", "file_hash", "source",
            "rsas_version", "stats", "created_at",
        )
        read_only_fields = fields

    def get_stats(self, obj: ScanBatch) -> dict[str, Any]:
        return dict(obj.stats_json or {})


class DryRunResultSerializer(serializers.Serializer):
    new = serializers.IntegerField(min_value=0)
    still_open = serializers.IntegerField(min_value=0)
    fixed_unverified = serializers.IntegerField(min_value=0)
    reopened = serializers.IntegerField(min_value=0)
    errors = serializers.ListField(child=serializers.DictField())
    skipped = serializers.BooleanField()
    file_hash = serializers.CharField()


__all__ = ["DryRunResultSerializer", "ScanBatchSerializer"]
