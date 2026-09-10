"""Task4 CMDB sync tests (RED first): sync summary counts, mapping history API,
retry-then-visible-failure on CMDB 500. All HTTP mocked — no real network."""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

import pytest
from django.test import Client
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.models import Role, User
from apps.assets.models import Asset, AssetOwnerMap
from apps.cmdb.client import CmdbClient, CmdbSyncError
from apps.cmdb.tasks import sync_cmdb
from apps.tickets.models import TicketState, VulnTicket


@pytest.fixture(autouse=True)
def _cmdb_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CMDB_BASE_URL", "https://cmdb.example")
    monkeypatch.setenv("CMDB_TOKEN", "test-token")
    monkeypatch.setenv("CMDB_CURSOR_FILE", "/tmp/cmdb_test_cursor")


def _page(items: list[dict[str, object]]) -> mock.Mock:
    resp = mock.Mock()
    resp.status_code = 200
    resp.json.return_value = {"results": items, "next": None}
    resp.raise_for_status.return_value = None
    return resp


@pytest.mark.django_db
def test_sync_upserts_remaps_dispatches_and_counts() -> None:
    owner_new: User = User.objects.create_user(username="n", wecom_userid="wecom-new")
    old_owner: User = User.objects.create_user(username="o", wecom_userid="wecom-old")
    asset: Asset = Asset.objects.create(ip="10.0.1.1", hostname="stale")
    AssetOwnerMap.objects.create(ip=asset, user=old_owner, valid_from=timezone.now())
    sla = timezone.now() + timedelta(days=7)
    ticket = VulnTicket.objects.create(
        dedup_key="k-10.0.1.1",
        ip="10.0.1.1",
        port=80,
        severity="高",
        state=TicketState.PENDING_ASSIGN,
        sla_due_at=sla,
    )
    payload = [
        {
            "ip": "10.0.1.1",
            "hostname": "fresh",
            "os": "linux",
            "dept": "ops",
            "owner_wecomid": "wecom-new",
            "status": "online",
        },
        {"ip": "10.0.9.9", "hostname": "ghost", "owner_wecomid": "", "status": "on"},
    ]
    with mock.patch("apps.cmdb.client.requests.get", return_value=_page(payload)):
        summary = sync_cmdb.run()

    assert summary["upserted"] == 2
    assert summary["remapped"] == 1  # 10.0.1.1 owner changed old -> new
    assert summary["orphaned"] == 1  # 10.0.9.9 has no owner -> ops-pool KPI
    asset.refresh_from_db()
    assert asset.hostname == "fresh"
    ticket.refresh_from_db()
    assert ticket.assignee_id == owner_new.id
    assert ticket.sla_due_at == sla
    assert AssetOwnerMap.objects.filter(ip=asset).count() >= 2


@pytest.mark.django_db
def test_sync_retries_then_fails_visibly_on_cmdb_500() -> None:
    bad = mock.Mock()
    bad.status_code = 500
    bad.json.return_value = {}
    import requests as _rq

    bad.raise_for_status.side_effect = _rq.HTTPError("500 Server Error")
    with mock.patch("apps.cmdb.client.requests.get", return_value=bad) as get:
        with mock.patch("apps.cmdb.client.time.sleep", return_value=None):
            with pytest.raises(CmdbSyncError):
                sync_cmdb.run()
    assert get.call_count >= 2  # retried with backoff before surfacing failure


@pytest.mark.django_db
def test_client_sends_updated_since_cursor() -> None:
    seen: dict[str, object] = {}

    def _fake_get(url: str, **kwargs: object) -> mock.Mock:
        seen.update(kwargs.get("params", {}))  # type: ignore[arg-type]
        return _page([])

    with mock.patch("apps.cmdb.client.requests.get", side_effect=_fake_get):
        CmdbClient(base_url="https://cmdb.example", token="t").fetch_assets("2024-01-01")
    assert seen.get("updated_since") == "2024-01-01"


def _authed(username: str, role: str) -> APIClient:
    password = "pw-sync-test-123"
    User.objects.create_user(
        username=username, password=password,
        wecom_userid=f"wecom-{username}", role=role,
    )
    client = APIClient()
    login = client.post(
        "/api/auth/local",
        {"username": username, "password": password},
        format="json",
    )
    assert login.status_code == 200, login.content
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['jwt']}")
    return client


@pytest.mark.django_db
def test_post_sync_view_returns_summary() -> None:
    User.objects.create_user(username="op", wecom_userid="wecom-op", is_staff=True)
    payload = [
        {"ip": "10.0.2.2", "hostname": "h", "owner_wecomid": "wecom-op"},
    ]
    api = _authed("sync_op", Role.OPERATOR)
    with mock.patch("apps.cmdb.client.requests.get", return_value=_page(payload)):
        resp = api.post("/api/cmdb/sync")
    assert resp.status_code == status.HTTP_200_OK
    body = resp.data
    assert (body["upserted"], body["remapped"], body["orphaned"]) == (1, 1, 0)


@pytest.mark.django_db
def test_sync_view_unauthenticated_denied() -> None:
    api = Client()
    assert api.post("/api/cmdb/sync").status_code in (401, 403)


@pytest.mark.django_db
def test_sync_view_operator_reaches_task_layer() -> None:
    api = _authed("sync_op2", Role.OPERATOR)
    summary = {"upserted": 3, "remapped": 1, "orphaned": 0}
    with mock.patch("apps.cmdb.views.sync_cmdb") as task:
        task.run.return_value = summary
        resp = api.post("/api/cmdb/sync")
    assert resp.status_code == status.HTTP_200_OK
    assert resp.data == summary


@pytest.mark.django_db
def test_mapping_view_returns_current_plus_history() -> None:
    u1: User = User.objects.create_user(username="u1", wecom_userid="w1")
    u2: User = User.objects.create_user(username="u2", wecom_userid="w2")
    asset: Asset = Asset.objects.create(ip="10.0.3.3", hostname="h3")
    AssetOwnerMap.objects.create(ip=asset, user=u1, valid_from=timezone.now())
    from apps.assets.dispatch import remap_owner

    remap_owner(asset, u2)

    api = _authed("map_op", Role.OPERATOR)
    resp = api.get("/api/assets/mapping", {"ip": "10.0.3.3"})
    assert resp.status_code == status.HTTP_200_OK
    body = resp.data
    assert body["current"]["wecom_userid"] == "w2"
    assert len(body["history"]) >= 2


@pytest.mark.django_db
def test_mapping_view_unauthenticated_denied() -> None:
    api = Client()
    assert api.get("/api/assets/mapping", {"ip": "10.0.3.3"}).status_code in (401, 403)
