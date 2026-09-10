"""Task4 dispatch matrix (RED first): remap keeps SLA clock, history grows,
unknown IP lands in the orphan pool (assignee NULL)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.accounts.models import User
from apps.assets.dispatch import (
    dispatch_ticket,
    dispatch_tickets_for_ip,
    get_current_owner,
    remap_owner,
)
from apps.assets.models import Asset, AssetOwnerMap
from apps.tickets.models import TicketState, VulnTicket


def _mkuser(username: str, wecom: str) -> User:
    return User.objects.create_user(username=username, wecom_userid=wecom)


def _mkticket(ip: str, sla_due: object) -> VulnTicket:
    return VulnTicket.objects.create(
        dedup_key=f"key-{ip}",
        ip=ip,
        port=443,
        severity="高",
        state=TicketState.PENDING_ASSIGN,
        sla_due_at=sla_due,  # type: ignore[arg-type]
    )


@pytest.mark.django_db
def test_dispatch_sets_assignee_without_touching_sla() -> None:
    owner: User = _mkuser("owner-a", "wecom-a")
    asset: Asset = Asset.objects.create(ip="10.0.0.11", hostname="web-11")
    remap_owner(asset, owner)
    sla = timezone.now() + timedelta(days=7)
    ticket: VulnTicket = _mkticket("10.0.0.11", sla)

    dispatch_ticket(ticket)

    ticket.refresh_from_db()
    assert ticket.assignee_id == owner.id
    assert ticket.sla_due_at == sla


@pytest.mark.django_db
def test_remap_keeps_sla_and_appends_history() -> None:
    owner_a: User = _mkuser("owner-a", "wecom-a")
    owner_b: User = _mkuser("owner-b", "wecom-b")
    asset: Asset = Asset.objects.create(ip="10.0.0.12", hostname="web-12")
    remap_owner(asset, owner_a)
    sla = timezone.now() + timedelta(days=30)
    ticket: VulnTicket = _mkticket("10.0.0.12", sla)

    dispatch_ticket(ticket)
    assert VulnTicket.objects.get(pk=ticket.pk).assignee_id == owner_a.id

    remap_owner(asset, owner_b)  # owner change: close-and-insert, NEVER in-place
    dispatch_tickets_for_ip("10.0.0.12")

    ticket.refresh_from_db()
    assert ticket.assignee_id == owner_b.id
    assert ticket.sla_due_at == sla  # SLA clock untouched by reassignment
    rows = AssetOwnerMap.objects.filter(ip=asset).order_by("valid_from")
    assert rows.count() >= 2
    assert rows[0].valid_to is not None  # old row closed
    assert rows[1].valid_to is None  # exactly one current row
    assert get_current_owner("10.0.0.12").id == owner_b.id  # type: ignore[union-attr]


@pytest.mark.django_db
def test_remap_same_owner_is_noop() -> None:
    owner: User = _mkuser("owner-a", "wecom-a")
    asset: Asset = Asset.objects.create(ip="10.0.0.13", hostname="web-13")
    remap_owner(asset, owner)

    remap_owner(asset, owner)

    assert AssetOwnerMap.objects.filter(ip=asset).count() == 1


@pytest.mark.django_db
def test_unknown_ip_goes_to_orphan_pool() -> None:
    sla = timezone.now() + timedelta(days=7)
    ticket: VulnTicket = _mkticket("192.0.2.99", sla)  # never seen by CMDB

    dispatch_ticket(ticket)

    ticket.refresh_from_db()
    assert ticket.assignee is None  # orphan: visible in ops pool via assignee NULL
    assert ticket.sla_due_at == sla
    assert get_current_owner("192.0.2.99") is None


@pytest.mark.django_db
def test_asset_without_owner_orphans_ticket() -> None:
    Asset.objects.create(ip="10.0.0.14", hostname="bare-metal")
    sla = timezone.now() + timedelta(days=7)
    ticket: VulnTicket = _mkticket("10.0.0.14", sla)

    dispatch_ticket(ticket)

    ticket.refresh_from_db()
    assert ticket.assignee is None
