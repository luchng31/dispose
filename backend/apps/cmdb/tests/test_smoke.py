from __future__ import annotations

import pytest
from django.apps import apps
from django.conf import settings


@pytest.mark.django_db
def test_cmdb_app_registered_smoke() -> None:
    assert apps.is_installed("apps.cmdb")
    assert "apps.cmdb" in settings.INSTALLED_APPS
