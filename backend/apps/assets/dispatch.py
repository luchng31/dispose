"""Owner-map history + ticket dispatch (Task4).

History rule: on owner change, CLOSE the old row (valid_to=now) and INSERT
a new row (valid_from=now). NEVER update a row in place — history is the
audit trail for "who owned this IP when".

Dispatch rule: ticket.assignee = current-valid owner user. Reassignment
never touches sla_due_at (SLA clock survives remap). No current map
(unknown IP or ownerless asset) -> assignee None = orphan pool, which the
ops pool view filters on (assignee IS NULL, Task6).
"""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from apps.accounts.models import User
from apps.assets.models import Asset, AssetOwnerMap
from apps.tickets.models import TicketState, VulnTicket

_OPEN_STATES: tuple[str, ...] = (
    TicketState.PENDING_ASSIGN,
    TicketState.PENDING_FIX,
    TicketState.PENDING_RETEST,
)


def get_current_owner(ip: str) -> User | None:
    """Current-valid owner for an IP, or None (orphan)."""
    row = (
        AssetOwnerMap.objects.filter(ip_id=ip, valid_to=None)
        .select_related("user")
        .order_by("-valid_from")
        .first()
    )
    return row.user if row is not None else None  # type: ignore[return-value]


@transaction.atomic
def remap_owner(asset: Asset, user: User | None) -> AssetOwnerMap | None:
    """Close-and-insert owner change. Same owner or both-empty is a no-op.

    Passing user=None closes the current row (asset became ownerless).
    """
    now = timezone.now()
    current = (
        AssetOwnerMap.objects.filter(ip=asset, valid_to=None)
        .order_by("-valid_from")
        .first()
    )
    current_uid = current.user_id if current is not None else None
    new_uid = user.id if user is not None else None
    if current_uid == new_uid:
        return current
    if current is not None:
        current.valid_to = now
        current.save(update_fields=["valid_to"])
    if user is None:
        return None
    return AssetOwnerMap.objects.create(ip=asset, user=user, valid_from=now)


def dispatch_ticket(ticket: VulnTicket) -> VulnTicket:
    """Assign one ticket to its IP's current owner; orphan (None) if unmapped.

    Only assignee is written — sla_due_at and all other fields are untouched.
    """
    owner = get_current_owner(ticket.ip)
    ticket.assignee = owner
    ticket.save(update_fields=["assignee"])
    return ticket


def dispatch_tickets_for_ip(ip: str) -> int:
    """Re-dispatch all open tickets for an IP after a remap. Returns count."""
    count = 0
    owner = get_current_owner(ip)
    tickets = VulnTicket.objects.filter(ip=ip, state__in=_OPEN_STATES)
    for ticket in tickets:
        ticket.assignee = owner
        ticket.save(update_fields=["assignee"])
        count += 1
    return count
