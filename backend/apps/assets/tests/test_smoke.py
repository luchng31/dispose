from __future__ import annotations

import pytest
from django.utils import timezone

from apps.accounts.models import User
from apps.assets.models import Asset, AssetOwnerMap


@pytest.mark.django_db
def test_create_asset_and_owner_map_smoke() -> None:
    user: User = User.objects.create_user(username="owner1", wecom_userid="owner1")
    asset: Asset = Asset.objects.create(ip="10.0.0.1", hostname="web-01")
    AssetOwnerMap.objects.create(ip=asset, user=user, valid_from=timezone.now())
    assert Asset.objects.filter(ip="10.0.0.1").exists()
    assert AssetOwnerMap.objects.filter(ip=asset, valid_to=None).count() == 1
