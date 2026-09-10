from __future__ import annotations

import threading
from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from apps.accounts.models import User

_state: threading.local = threading.local()


def set_current_actor(user: User | None) -> None:
    _state.actor = user


def get_current_actor() -> User | None:
    actor: User | None = getattr(_state, "actor", None)
    return actor if isinstance(actor, User) else None


def clear_current_actor() -> None:
    if hasattr(_state, "actor"):
        del _state.actor


class AuditActorMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response: Callable[[HttpRequest], HttpResponse] = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user: object = getattr(request, "user", None)
        set_current_actor(user if isinstance(user, User) else None)
        try:
            response: HttpResponse = self.get_response(request)
        finally:
            clear_current_actor()
        client_ip: str = str(request.META.get("REMOTE_ADDR", ""))
        response["X-Audit-Actor"] = (
            str(getattr(user, "username", "")) if isinstance(user, User) else ""
        )
        _ = client_ip
        return response
