"""Operator-triggered CMDB pull: POST /api/cmdb/sync -> {upserted, remapped, orphaned}.

Runs the sync synchronously: via .delay().get() when
CELERY_TASK_ALWAYS_EAGER is on, else a direct .run() call (no broker needed
in test/dev). CMDB-side failure surfaces as HTTP 502 with the retry-exhausted
reason so ops can see it.

Auth: operator/leader only (IsAuthenticated + IsOperatorOrLeader).
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.cmdb.client import CmdbSyncError
from apps.cmdb.tasks import sync_cmdb
from apps.tickets.views import IsOperatorOrLeader


class CmdbSyncView(APIView):
    permission_classes = [IsAuthenticated, IsOperatorOrLeader]

    def post(self, request: Request) -> Response:
        try:
            if getattr(settings, "CELERY_TASK_ALWAYS_EAGER", False):
                result: Any = sync_cmdb.delay()
                summary = result.get() if hasattr(result, "get") else result
            else:
                summary = sync_cmdb.run()
        except CmdbSyncError as exc:
            return Response(
                {"detail": str(exc)}, status=status.HTTP_502_BAD_GATEWAY
            )
        return Response(summary, status=status.HTTP_200_OK)
