from __future__ import annotations

import pytest

from apps.imports.models import BatchSource, ScanBatch


@pytest.mark.django_db
def test_create_scan_batch_smoke() -> None:
    batch: ScanBatch = ScanBatch.objects.create(
        file_name="rsas_20260101.zip",
        file_hash="a" * 64,
        source=BatchSource.MANUAL,
    )
    assert ScanBatch.objects.filter(file_hash="a" * 64).exists()
    assert batch.source == BatchSource.MANUAL
