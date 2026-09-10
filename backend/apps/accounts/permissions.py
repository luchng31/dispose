from __future__ import annotations

from collections.abc import Sequence

from django.db.models import QuerySet
from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

from apps.accounts.models import Role, User
from apps.tickets.models import VulnTicket

OPERATOR_ROLES: frozenset[str] = frozenset({Role.ADMIN, Role.OPERATOR})
READ_ALL_ROLES: frozenset[str] = frozenset(
    {Role.ADMIN, Role.OPERATOR, Role.LEADER, Role.AUDITOR}
)


def get_my_ips(user: User) -> list[str]:
    from apps.assets.models import AssetOwnerMap

    if user.role in READ_ALL_ROLES and user.role != Role.OWNER:
        return []
    rows: Sequence[str] = list(
        AssetOwnerMap.objects.filter(user_id=user.pk, valid_to__isnull=True).values_list(
            "ip_id", flat=True
        )
    )
    return [str(ip) for ip in rows]


def get_visible_tickets(user: User) -> QuerySet[VulnTicket]:
    if user.role == Role.OWNER:
        return VulnTicket.objects.filter(ip__in=get_my_ips(user))
    return VulnTicket.objects.all()


def can_close(user: User) -> bool:
    return user.role in OPERATOR_ROLES


def can_approve_delay(user: User) -> bool:
    return user.role in frozenset({Role.ADMIN, Role.OPERATOR, Role.LEADER})


class IsOperator(BasePermission):
    def has_permission(self, request: Request, view: APIView) -> bool:
        user: object = request.user
        return (
            isinstance(user, User)
            and user.is_authenticated
            and user.role in OPERATOR_ROLES
        )


class IsAdminRole(BasePermission):
    def has_permission(self, request: Request, view: APIView) -> bool:
        user: object = request.user
        return isinstance(user, User) and user.is_authenticated and user.role == Role.ADMIN


class IsAuditorReadOnly(BasePermission):
    def has_permission(self, request: Request, view: APIView) -> bool:
        user: object = request.user
        if not (isinstance(user, User) and user.is_authenticated):
            return False
        if user.role == Role.AUDITOR and request.method not in SAFE_METHODS:
            return False
        return True


class IsOwnerScoped(BasePermission):
    def has_permission(self, request: Request, view: APIView) -> bool:
        user: object = request.user
        return isinstance(user, User) and user.is_authenticated

    def has_object_permission(
        self, request: Request, view: APIView, obj: VulnTicket
    ) -> bool:
        user: object = request.user
        if not (isinstance(user, User) and user.is_authenticated):
            return False
        if user.role in READ_ALL_ROLES:
            return True
        return obj.ip in get_my_ips(user)
