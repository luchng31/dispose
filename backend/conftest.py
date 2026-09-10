"""Pytest isolation: clear the default cache before each test.

The sysconfig store memoizes DB-backed config in the default cache
(LocMem under DB_ENGINE=sqlite). Without a per-test reset, rows rolled
back by the ``db`` fixture would leave warm cache entries visible to
later tests. Clearing here keeps the suite deterministic.
"""

from __future__ import annotations

import pytest
from django.core.cache import cache


@pytest.fixture(autouse=True)
def _clear_default_cache() -> None:
    try:
        cache.clear()
    except Exception:
        pass
    yield
    try:
        cache.clear()
    except Exception:
        pass
