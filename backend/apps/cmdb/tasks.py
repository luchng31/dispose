"""Hourly CMDB pull (Task4). Celery task + sync core.

Flow: read updated_since cursor -> CmdbClient.fetch_assets -> upsert Asset
-> close-and-insert AssetOwnerMap via dispatch.remap_owner -> re-dispatch
open tickets for the IP (SLA clock untouched) -> save cursor -> summary.

Cursor: best-effort local file (CMDB_CURSOR_FILE env, default
/tmp/cmdb_updated_since) so hourly beat skips already-seen rows. PRODUCTION
NOTE (Task9): move this cursor into Redis/DB alongside the beat schedule;
the file exists only to avoid over-engineering a new model in Task4.

sync_cmdb is a real Celery task (bind=True) AND directly callable via
.run() in tests without a broker. CMDB failures raise CmdbSyncError after
client-side retry — the view maps that to HTTP 502 (visible failure).
"""

from __future__ import annotations

import os
from typing import Any

from django.utils import timezone

from apps.accounts.models import User
from apps.assets.dispatch import (
    dispatch_tickets_for_ip,
    get_current_owner,
    remap_owner,
)
from apps.assets.models import Asset, AssetStatus
from apps.cmdb.client import CmdbAsset, CmdbClient

try:
    from celery import shared_task as _shared_task
except ImportError:  # celery absent in minimal test envs
    _shared_task = None  # type: ignore[assignment]


CURSOR_ENV_VAR = "CMDB_CURSOR_FILE"
DEFAULT_CURSOR_FILE = "/tmp/cmdb_updated_since"

_KNOWN_STATUSES: frozenset[str] = frozenset(
    {AssetStatus.ONLINE, AssetStatus.OFFLINE, AssetStatus.UNKNOWN}
)


def cursor_path() -> str:
    return os.environ.get(CURSOR_ENV_VAR, DEFAULT_CURSOR_FILE)


def load_cursor() -> str | None:
    try:
        with open(cursor_path(), encoding="utf-8") as fh:
            value = fh.read().strip()
            return value or None
    except OSError:
        return None


def save_cursor(value: str) -> None:
    try:
        with open(cursor_path(), "w", encoding="utf-8") as fh:
            fh.write(value)
    except OSError:
        pass  # cursor is best-effort; sync results are already committed


def _normalize_status(raw: str) -> str:
    value = (raw or "").strip().lower()
    return value if value in _KNOWN_STATUSES else AssetStatus.UNKNOWN


def _resolve_user(wecom_id: str, dept: str) -> User | None:
    """Map CMDB owner_wecomid to a local user, auto-provisioning the stub.

    Returns None when CMDB names no owner (orphan path). Auto-provision keeps
    dispatch working before the user ever logs in via WeCom (Task2).
    """
    if not wecom_id:
        return None
    user, _ = User.objects.get_or_create(
        wecom_userid=wecom_id, defaults={"username": wecom_id, "dept": dept}
    )
    if dept and user.dept != dept:
        user.dept = dept
        user.save(update_fields=["dept"])
    return user


def _upsert_asset(item: CmdbAsset) -> tuple[Asset, bool]:
    asset, created = Asset.objects.get_or_create(
        ip=item["ip"],
        defaults={
            "hostname": item.get("hostname", ""),
            "os": item.get("os", ""),
            "biz_system": item.get("dept", ""),
            "status": _normalize_status(item.get("status", "")),
        },
    )
    if created:
        return asset, True
    changed = False
    for field, key in (
        ("hostname", "hostname"),
        ("os", "os"),
        ("biz_system", "dept"),
    ):
        new_value = item.get(key, "")
        if getattr(asset, field) != new_value:
            setattr(asset, field, new_value)
            changed = True
    new_status = _normalize_status(item.get("status", ""))
    if asset.status != new_status:
        asset.status = new_status
        changed = True
    if changed:
        asset.save()
    return asset, changed


def run_sync(updated_since: str | None = None) -> dict[str, int]:
    """Sync core (pure Django, no Celery needed). Returns summary counts."""
    cursor = updated_since if updated_since is not None else load_cursor()
    client = CmdbClient()
    items = client.fetch_assets(cursor)
    upserted = 0
    remapped = 0
    orphaned = 0
    for item in items:
        if not item.get("ip"):
            continue
        asset, changed = _upsert_asset(item)
        if changed:
            upserted += 1
        before = get_current_owner(asset.ip)
        before_id = before.id if before is not None else None
        user = _resolve_user(item.get("owner_wecomid", ""), item.get("dept", ""))
        remap_owner(asset, user)
        after = get_current_owner(asset.ip)
        after_id = after.id if after is not None else None
        if before_id != after_id:
            remapped += 1
        dispatch_tickets_for_ip(asset.ip)
        if after is None:
            orphaned += 1
    save_cursor(timezone.now().isoformat())
    return {"upserted": upserted, "remapped": remapped, "orphaned": orphaned}


def _sync_impl(updated_since: str | None = None) -> dict[str, int]:
    return run_sync(updated_since)


if _shared_task is not None:

    @_shared_task(name="cmdb.sync_cmdb", bind=True, max_retries=3)
    def sync_cmdb(self: Any, updated_since: str | None = None) -> dict[str, int]:
        return _sync_impl(updated_since)

else:  # pragma: no cover - fallback when celery is not installed

    class _EagerTask:
        def run(self, updated_since: str | None = None) -> dict[str, int]:
            return _sync_impl(updated_since)

        def delay(self, updated_since: str | None = None) -> dict[str, int]:
            return self.run(updated_since)

    sync_cmdb = _EagerTask()  # type: ignore[assignment]
