from __future__ import annotations

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.audit.middleware import get_current_actor
from apps.audit.models import AuditLog
from apps.tickets.models import VulnTicket

TRACKED_FIELDS: tuple[str, ...] = (
    "state",
    "assignee_id",
    "severity",
    "fix_evidence",
    "delay_until",
    "ignore_reason",
    "sla_due_at",
)


def _snapshot(ticket: VulnTicket) -> dict[str, object]:
    return {field: getattr(ticket, field, None) for field in TRACKED_FIELDS}


@receiver(pre_save, sender=VulnTicket)
def snapshot_ticket_before_write(
    sender: type[VulnTicket], instance: VulnTicket, **kwargs: object
) -> None:
    if instance.pk is None:
        return
    try:
        stored: VulnTicket = VulnTicket.objects.get(pk=instance.pk)
    except VulnTicket.DoesNotExist:
        return
    instance._pre_save_snapshot = _snapshot(stored)


@receiver(post_save, sender=VulnTicket)
def record_ticket_write(
    sender: type[VulnTicket], instance: VulnTicket, created: bool, **kwargs: object
) -> None:
    actor = get_current_actor()
    previous: dict[str, object] = getattr(instance, "_pre_save_snapshot", {})
    current: dict[str, object] = _snapshot(instance)
    if created:
        diff: dict[str, object] = {"created": True, "fields": _jsonable(current)}
        action: str = "ticket.create"
    else:
        changed: dict[str, object] = {
            key: {"old": _jsonable_value(previous.get(key)), "new": _jsonable_value(value)}
            for key, value in current.items()
            if _jsonable_value(previous.get(key)) != _jsonable_value(value)
        }
        if not changed:
            return
        diff = {"changed": changed}
        action = "ticket.update"
    AuditLog.objects.create(
        actor=actor,
        action=action,
        ticket=instance,
        entity="vuln_ticket",
        entity_id=str(instance.pk),
        diff_json=diff,
    )


def _jsonable(mapping: dict[str, object]) -> dict[str, object]:
    return {key: _jsonable_value(value) for key, value in mapping.items()}


def _jsonable_value(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)
