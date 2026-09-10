"""Minimal CORS middleware (zero new dependencies).

Allows browser clients served from a different origin (e.g. Vite dev
``http://localhost:5173`` while the API runs on ``:8000``) to call the API.
Origins come from the ``CORS_ALLOWED_ORIGINS`` env var (comma-separated);
``*`` is deliberately NOT supported — reflect the request Origin only when
it is allow-listed.
"""

from __future__ import annotations

from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse


def _allowed_origins() -> set[str]:
    raw: str = getattr(settings, "CORS_ALLOWED_ORIGINS", "")
    return {o.strip() for o in raw.split(",") if o.strip()}


class CorsMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        origin = request.headers.get("Origin", "")
        if request.method == "OPTIONS" and origin in _allowed_origins():
            response = HttpResponse(status=204)
        else:
            response = self.get_response(request)
        if origin in _allowed_origins():
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            response["Access-Control-Max-Age"] = "86400"
        return response
