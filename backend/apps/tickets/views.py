"""Task6 REST surface: my-tickets, ops-pool, dashboard, audit.

Isolation: every ticket list/detail queryset starts from
get_visible_tickets() (owner sees only own IPs). Every state change goes
through transition() (ValidationError -> 422, PermissionDenied -> 403).
Audit rows are written by Task2's post_save signal + Task5's _record_audit
inside transition(); views never hand-write audit rows.

Auth: JWTAuthentication via DEFAULT_AUTHENTICATION_CLASSES; auditor is
read-only (IsAuditorReadOnly) on all write endpoints.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import uuid
from datetime import datetime
from io import StringIO
from typing import Any

from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Count, Prefetch, Q, QuerySet
from django.http import HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import generics, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import Role, User
from apps.accounts.permissions import (
    IsAdminRole,
    IsAuditorReadOnly,
    IsOperator,
    get_visible_tickets,
)
from apps.assets.dispatch import get_current_owner
from apps.audit.models import AuditLog
from apps.imports.models import BatchSource, ScanBatch
from apps.tickets.filters import (
    SEVERITY_VALUES,
    STATE_VALUES,
    FilterValidationError,
    apply_my_filters,
    apply_pool_filters,
)
from apps.tickets.models import (
    DelayRequest,
    DelayRequestStatus,
    SlaPolicy,
    TicketAttachment,
    TicketState,
    VulnTicket,
)
from apps.tickets.serializers import (
    AttachmentSerializer,
    AuditLogSerializer,
    DelayInputSerializer,
    DelayRequestSerializer,
    IgnoreInputSerializer,
    NoteInputSerializer,
    SubmitInputSerializer,
    VulnTicketDetailSerializer,
    VulnTicketListSerializer,
    assignee_name,
    source_label,
    ticket_title,
)
from apps.tickets.sla import FALLBACK_SLA_DAYS, compute_due
from apps.tickets.transitions import _delay_days, transition

HTTP_UNPROCESSABLE: int = 422

MAX_ATTACHMENT_BYTES: int = 5 * 1024 * 1024
ALLOWED_IMAGE_TYPES: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp"}
)
ALLOWED_IMAGE_EXTS: frozenset[str] = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp"})


def _sniff_image(header: bytes) -> bool:
    if header[:4] == b"\x89PNG":
        return True
    if header[:3] == b"\xff\xd8\xff":
        return True
    if header[:6] in (b"GIF87a", b"GIF89a"):
        return True
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return True
    return False

# SLA at-risk window (days before sla_due_at); overdue = past due & still open.
AT_RISK_DAYS: int = 3
OPEN_STATES: list[str] = [
    TicketState.PENDING_ASSIGN,
    TicketState.PENDING_FIX,
    TicketState.PENDING_RETEST,
    TicketState.DELAYED,
]


class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


class IsOperatorOrLeader(BasePermission):
    """Ops-pool readers: admin/operator/leader (auditor/owner excluded)."""

    message = "operator or leader role required"

    def has_permission(self, request: Request, view: APIView) -> bool:
        user: object = request.user
        return (
            isinstance(user, User)
            and user.is_authenticated
            and user.role in frozenset({Role.ADMIN, Role.OPERATOR, Role.LEADER})
        )


class IsAuditViewer(BasePermission):
    """Audit readers: admin/operator/auditor, read-only surface."""

    message = "audit viewer role required"

    def has_permission(self, request: Request, view: APIView) -> bool:
        user: object = request.user
        return (
            isinstance(user, User)
            and user.is_authenticated
            and user.role in frozenset({Role.ADMIN, Role.OPERATOR, Role.AUDITOR})
        )


def _actor(request: Request) -> User:
    user: object = request.user
    assert isinstance(user, User)
    return user


def _visible(user: User) -> QuerySet[VulnTicket]:
    return get_visible_tickets(user).select_related("assignee", "batch").order_by("-updated_at", "-id")


def _transition_response(
    ticket: VulnTicket, to_state: str, role: str, payload: dict[str, Any]
) -> Response:
    try:
        out: VulnTicket = transition(ticket, to_state, actor_role=role, payload=payload)
    except DjangoValidationError as exc:
        return Response(
            {"detail": "; ".join(exc.messages)},
            status=HTTP_UNPROCESSABLE,
        )
    except PermissionDenied as exc:
        return Response(
            {"detail": str(exc) or "forbidden"},
            status=status.HTTP_403_FORBIDDEN,
        )
    return Response(VulnTicketDetailSerializer(out).data, status=status.HTTP_200_OK)


def _remember_note(ticket_id: int, key: str, value: str) -> None:
    """Attach a closure/ignore note into fix_evidence JSON (frozen schema).

    Runs through the normal save path so Task2's audit signal records it;
    never writes audit rows directly.
    """
    if not value:
        return
    ticket: VulnTicket = VulnTicket.objects.get(pk=ticket_id)
    evidence: dict[str, Any] = dict(ticket.fix_evidence or {})
    evidence[key] = value
    ticket.fix_evidence = evidence
    ticket.save(update_fields=["fix_evidence", "updated_at"])


class MyTicketListView(generics.ListAPIView):
    """GET /api/tickets/my?state=&severity=&q= (owner-isolated, paginated)."""

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]
    serializer_class = VulnTicketListSerializer
    pagination_class = StandardPagination

    def get_queryset(self) -> QuerySet[VulnTicket]:
        qs: QuerySet[VulnTicket] = _visible(_actor(self.request))
        params: dict[str, str] = {k: v for k, v in self.request.query_params.items()}
        try:
            return apply_my_filters(qs, params)
        except FilterValidationError as exc:
            from rest_framework.exceptions import ValidationError as DRFValidationError

            raise DRFValidationError({"detail": exc.detail, "allowed": exc.allowed}) from exc


def _csv_safe(v: Any) -> Any:
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        return "'" + v
    return v


def _write_ticket_csv_rows(writer: Any, qs: QuerySet[VulnTicket], limit: int) -> None:
    writer.writerow(
        ["ID", "IP", "端口", "严重性", "状态", "标题", "负责人", "SLA截止", "创建时间", "发现日期", "来源"]
    )
    for t in qs[:limit].iterator(chunk_size=2000):
        writer.writerow(
            [
                t.pk,
                _csv_safe(t.ip),
                t.port,
                _csv_safe(t.severity),
                _csv_safe(t.state),
                _csv_safe(ticket_title(t)),
                _csv_safe(assignee_name(t) or ""),
                _csv_safe(t.sla_due_at.isoformat() if t.sla_due_at else ""),
                _csv_safe(t.created_at.isoformat()),
                _csv_safe(t.first_seen_at.isoformat() if t.first_seen_at else ""),
                _csv_safe(source_label(t) or ""),
            ]
        )


class MyTicketExportView(APIView):
    """GET /api/tickets/my/export?state=&severity=&q= (owner-isolated CSV).

    Same visibility + filters as GET /api/tickets/my; UTF-8 BOM, capped at
    EXPORT_MAX_ROWS. Lets owners export their own ledger (pool export is
    operator/leader only).
    """

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    def get(self, request: Request) -> Response | HttpResponse:
        qs: QuerySet[VulnTicket] = _visible(_actor(request))
        params: dict[str, str] = {k: v for k, v in request.query_params.items()}
        try:
            qs = apply_my_filters(qs, params)
        except FilterValidationError as exc:
            return Response(
                {"detail": exc.detail, "allowed": exc.allowed},
                status=status.HTTP_400_BAD_REQUEST,
            )
        buf = StringIO()
        _write_ticket_csv_rows(csv.writer(buf), qs, EXPORT_MAX_ROWS)
        resp = HttpResponse("\ufeff" + buf.getvalue(), content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = 'attachment; filename="my_tickets.csv"'
        return resp


MAX_IP_SUMMARY_ROWS: int = 500


class IpSummaryView(APIView):
    """GET /api/tickets/ip-summary?state=&severity=&q= (owner-isolated, unpaginated).

    Server-side per-IP rollup over the FULL filtered set (the list endpoint
    only sees one page, so client-side group-by undercounts). Same visibility
    and filter contract as GET /api/tickets/my; bad state/severity -> 400.
    """

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    def get(self, request: Request) -> Response:
        qs: QuerySet[VulnTicket] = _visible(_actor(request))
        params: dict[str, str] = {k: v for k, v in request.query_params.items()}
        try:
            qs = apply_my_filters(qs, params)
        except FilterValidationError as exc:
            return Response(
                {"detail": exc.detail, "allowed": exc.allowed},
                status=status.HTTP_400_BAD_REQUEST,
            )
        now = timezone.now()
        open_q: Q = Q(sla_due_at__lt=now) & ~Q(state__in=[TicketState.CLOSED, TicketState.IGNORED])
        annotations: dict[str, object] = {
            "total": Count("id"),
            "overdue": Count("id", filter=open_q),
        }
        for severity in SEVERITY_VALUES:
            annotations[f"sev_{severity}"] = Count("id", filter=Q(severity=severity))
        rows = qs.values("ip").annotate(**annotations).order_by("-total", "ip")[:MAX_IP_SUMMARY_ROWS]
        results: list[dict[str, object]] = [
            {
                "ip": row["ip"],
                "total": row["total"],
                "overdue": row["overdue"],
                "severities": {severity: row[f"sev_{severity}"] for severity in SEVERITY_VALUES},
            }
            for row in rows
        ]
        return Response({"results": results})


class TicketDetailView(generics.RetrieveAPIView):
    """GET /api/tickets/:id (404 when not visible to the caller)."""

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]
    serializer_class = VulnTicketDetailSerializer
    lookup_url_kwarg = "pk"

    def get_queryset(self) -> QuerySet[VulnTicket]:
        return _visible(_actor(self.request)).prefetch_related(
            Prefetch(
                "audit_logs",
                queryset=AuditLog.objects.select_related("actor").order_by(
                    "created_at", "id"
                ),
                to_attr="prefetched_timeline",
            ),
            Prefetch(
                "attachments",
                queryset=TicketAttachment.objects.select_related(
                    "uploaded_by"
                ).order_by("created_at", "id"),
                to_attr="prefetched_attachments",
            ),
        )


class TicketSubmitView(APIView):
    """POST /api/tickets/:id/submit {evidence} (待修复->待复测)."""

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = get_visible_tickets(user).filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        form = SubmitInputSerializer(data=request.data)
        if not form.is_valid():
            return Response(form.errors, status=HTTP_UNPROCESSABLE)
        evidence: dict[str, Any] = dict(form.validated_data.get("evidence", {}))
        resp: Response = _transition_response(
            ticket, TicketState.PENDING_RETEST, user.role, {"fix_evidence": evidence}
        )
        return resp



class TicketDelayView(APIView):
    """POST /api/tickets/:id/delay {delay_until|delay_days, reason}.

    Approval rules live inside transition() (owner 403, leader >30d needs
    operator co-approval); the view only parses input and maps errors.
    """

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = get_visible_tickets(user).filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        form = DelayInputSerializer(data=request.data)
        if not form.is_valid():
            return Response(form.errors, status=HTTP_UNPROCESSABLE)
        payload: dict[str, Any] = {
            "reason": str(form.validated_data.get("reason", "")),
        }
        if form.validated_data.get("delay_days") is not None:
            payload["delay_days"] = int(form.validated_data["delay_days"])
        if form.validated_data.get("delay_until") is not None:
            until: datetime = form.validated_data["delay_until"]
            payload["delay_until"] = until
        co_approved: str = str(form.validated_data.get("co_approved_by", ""))
        if co_approved:
            payload["co_approved_by"] = co_approved
        return _transition_response(ticket, TicketState.DELAYED, user.role, payload)


class TicketDelayRequestView(APIView):
    """POST /api/tickets/:id/delay-request (owner 申请延期, 待修复 only)."""

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = get_visible_tickets(user).filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        if ticket.state != TicketState.PENDING_FIX:
            return Response(
                {"detail": f"仅待修复工单可申请延期（当前：{ticket.state}）"},
                status=HTTP_UNPROCESSABLE,
            )
        form = DelayInputSerializer(data=request.data)
        if not form.is_valid():
            return Response(form.errors, status=HTTP_UNPROCESSABLE)
        reason: str = str(form.validated_data.get("reason", "") or "").strip()
        if not reason:
            return Response({"detail": "请填写延期原因"}, status=status.HTTP_400_BAD_REQUEST)
        if DelayRequest.objects.filter(
            ticket=ticket, status=DelayRequestStatus.PENDING
        ).exists():
            return Response(
                {"detail": "该工单已有待审批的延期申请"},
                status=HTTP_UNPROCESSABLE,
            )
        req = DelayRequest.objects.create(
            ticket=ticket,
            requested_by=user,
            delay_days=form.validated_data.get("delay_days"),
            delay_until=form.validated_data.get("delay_until"),
            reason=reason,
        )
        return Response(DelayRequestSerializer(req).data, status=status.HTTP_201_CREATED)


class OpsDelayRequestListView(generics.ListAPIView):
    """GET /api/ops/delay-requests?status= (operator/leader only)."""

    permission_classes = [IsAuthenticated, IsOperatorOrLeader]
    serializer_class = DelayRequestSerializer
    pagination_class = StandardPagination

    def get_queryset(self) -> QuerySet[DelayRequest]:
        qs: QuerySet[DelayRequest] = DelayRequest.objects.select_related(
            "ticket", "requested_by", "decided_by"
        ).order_by("-created_at", "-id")
        state: str = str(self.request.query_params.get("status", "") or "").strip()
        if state:
            if state not in (
                DelayRequestStatus.PENDING,
                DelayRequestStatus.APPROVED,
                DelayRequestStatus.REJECTED,
            ):
                from rest_framework.exceptions import (
                    ValidationError as DRFValidationError,
                )

                raise DRFValidationError({"detail": f"未知状态：{state}"})
            qs = qs.filter(status=state)
        return qs


class OpsDelayDecideView(APIView):
    """POST /api/ops/delay-requests/:id/approve|reject (operator/leader).

    Leader 只能批 ≤30 天, 超过需运营. 批准后走 transition 待修复→已延期.
    """

    permission_classes = [IsAuthenticated, IsOperatorOrLeader]

    def post(self, request: Request, pk: int, action: str) -> Response:
        user: User = _actor(request)
        req: DelayRequest | None = DelayRequest.objects.select_related("ticket").filter(
            pk=pk
        ).first()
        if req is None:
            return Response({"detail": "申请不存在"}, status=status.HTTP_404_NOT_FOUND)
        if req.status != DelayRequestStatus.PENDING:
            return Response(
                {"detail": f"该申请已处理（{req.status}）"},
                status=HTTP_UNPROCESSABLE,
            )
        if action == "reject":
            return self._reject(req, user, request)
        if action == "approve":
            return self._approve(req, user)
        return Response({"detail": f"未知动作：{action}"}, status=status.HTTP_404_NOT_FOUND)

    def _reject(self, req: DelayRequest, user: User, request: Request) -> Response:
        note: str = str(request.data.get("note", "") or "").strip()
        req.status = DelayRequestStatus.REJECTED
        req.decided_by = user
        req.decided_at = timezone.now()
        req.decide_note = note
        req.save()
        return Response(DelayRequestSerializer(req).data)

    def _approve(self, req: DelayRequest, user: User) -> Response:
        payload: dict[str, Any] = {}
        if req.delay_days is not None:
            payload["delay_days"] = req.delay_days
        if req.delay_until is not None:
            payload["delay_until"] = req.delay_until
        try:
            days: int = _delay_days(payload)
        except DjangoValidationError as exc:
            return Response(
                {"detail": "; ".join(exc.messages)}, status=HTTP_UNPROCESSABLE
            )
        if user.role == Role.LEADER and days > 30:
            return Response(
                {"detail": "超过30天的延期需运营审批"},
                status=status.HTTP_403_FORBIDDEN,
            )
        ticket: VulnTicket = req.ticket
        resp: Response = _transition_response(ticket, TicketState.DELAYED, user.role, payload)
        if resp.status_code != 200:
            return resp
        req.status = DelayRequestStatus.APPROVED
        req.decided_by = user
        req.decided_at = timezone.now()
        req.save()
        return Response(DelayRequestSerializer(req).data)


class TicketResumeView(APIView):
    """POST /api/tickets/:id/resume (已延期->待修复, delay ends, work resumes)."""

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = get_visible_tickets(user).filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        return _transition_response(ticket, TicketState.PENDING_FIX, user.role, {})


class TicketAttachmentUploadView(APIView):
    """POST /api/tickets/:id/attachments (multipart file=, images only, 5MB)."""

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = get_visible_tickets(user).filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        upload = request.FILES.get("file")
        if upload is None:
            return Response({"detail": "缺少 file 字段"}, status=status.HTTP_400_BAD_REQUEST)
        content_type = str(getattr(upload, "content_type", "") or "")
        name = str(getattr(upload, "name", "") or "")
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if content_type not in ALLOWED_IMAGE_TYPES or ext not in ALLOWED_IMAGE_EXTS:
            return Response(
                {"detail": "仅支持 png/jpg/gif/webp 图片"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if upload.size is not None and upload.size > MAX_ATTACHMENT_BYTES:
            return Response(
                {"detail": "图片超过 5MB"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        header = upload.read(12)
        upload.seek(0)
        if not _sniff_image(header):
            return Response(
                {"detail": "文件头与图片格式不符"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        attachment = TicketAttachment.objects.create(
            ticket=ticket, file=upload, uploaded_by=user
        )
        data = AttachmentSerializer(attachment, context={"request": request}).data
        return Response(data, status=status.HTTP_201_CREATED)


class OpsAssignView(APIView):
    """POST /api/ops/:id/assign {assignee} (operator only, manual dispatch).

    assignee is a username; must be an active non-auditor user. 待分配 tickets
    move to 待修复 via transition(); tickets in other open states are
    reassigned in place (改派, SLA clock untouched). Closed/ignored -> 422.
    """

    permission_classes = [IsOperator]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = VulnTicket.objects.filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        if ticket.state in (TicketState.CLOSED, TicketState.IGNORED):
            return Response(
                {"detail": f"已关闭/已忽略的工单不可派单（当前：{ticket.state}）"},
                status=HTTP_UNPROCESSABLE,
            )
        username = str(request.data.get("assignee", "") or "").strip()
        if not username:
            return Response({"detail": "缺少 assignee（用户名）"}, status=status.HTTP_400_BAD_REQUEST)
        target: User | None = User.objects.filter(username=username).first()
        if target is None or not target.is_active:
            return Response(
                {"detail": f"用户不存在或已停用：{username}"},
                status=status.HTTP_404_NOT_FOUND,
            )
        if target.role == Role.AUDITOR:
            return Response(
                {"detail": "审计员不可作为处理人"},
                status=HTTP_UNPROCESSABLE,
            )
        if ticket.state == TicketState.PENDING_ASSIGN:
            ticket.assignee = target
            ticket.save(update_fields=["assignee", "updated_at"])
            resp: Response = _transition_response(ticket, TicketState.PENDING_FIX, user.role, {})
            if resp.status_code != 200:
                return resp
        else:
            ticket.assignee = target
            ticket.save()
        refreshed: VulnTicket = VulnTicket.objects.get(pk=ticket.pk)
        return Response(VulnTicketDetailSerializer(refreshed).data)


REMIND_COOLDOWN_HOURS: int = 24


class OpsRemindView(APIView):
    """POST /api/ops/remind {ids[]} (operator) — 手动提醒邮件（防轰炸）.

    Groups the selected open tickets by assignee and sends ONE aggregated
    email per assignee. Anti-bombing: tickets reminded within
    REMIND_COOLDOWN_HOURS (fix_evidence.last_reminded_at) are skipped and
    reported; unassigned tickets are skipped; a mail is only marked
    (fix_evidence.last_reminded_at + AuditLog ticket.remind) when actually
    sent (SMTP off -> sent_emails 0, retry later). -> 200
    {requested, sent_emails, reminded_tickets, skipped_cooldown,
    skipped_unassigned}.
    """

    permission_classes = [IsOperator]

    def post(self, request: Request) -> Response:
        user: User = _actor(request)
        ids = request.data.get("ids")
        if not isinstance(ids, list) or not ids or len(ids) > 500:
            return Response(
                {"detail": "ids 需为 1-500 的工单ID数组"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            id_list = [int(i) for i in ids]
        except (TypeError, ValueError):
            return Response({"detail": "ids 需为整数数组"}, status=status.HTTP_400_BAD_REQUEST)
        now = timezone.now()
        cutoff = now - timezone.timedelta(hours=REMIND_COOLDOWN_HOURS)
        tickets = (
            VulnTicket.objects.filter(pk__in=id_list)
            .exclude(state__in=[TicketState.CLOSED, TicketState.IGNORED])
            .select_related("assignee")
        )
        groups: dict[User, list[VulnTicket]] = {}
        skipped_cooldown = 0
        skipped_unassigned = 0
        seen: set[int] = set()
        for ticket in tickets:
            if ticket.pk in seen:
                continue
            seen.add(ticket.pk)
            if ticket.assignee is None:
                skipped_unassigned += 1
                continue
            last = str((ticket.fix_evidence or {}).get("last_reminded_at", "") or "")
            parsed = parse_datetime(last) if last else None
            if parsed is not None and parsed > cutoff:
                skipped_cooldown += 1
                continue
            groups.setdefault(ticket.assignee, []).append(ticket)

        from apps.notify.mailer import send_ticket_mail, ticket_line, user_email

        sent_emails = 0
        reminded = 0
        for assignee, ts in groups.items():
            to = [user_email(assignee)]
            body = "以下工单需要您尽快处理：\n" + "\n".join(ticket_line(t) for t in ts)
            sent = send_ticket_mail(
                to, f"漏洞处理提醒：{len(ts)} 张工单待处理", body
            )
            if sent <= 0:
                continue
            sent_emails += 1
            reminded += len(ts)
            for t in ts:
                evidence = dict(t.fix_evidence or {})
                evidence["last_reminded_at"] = now.isoformat()
                t.fix_evidence = evidence
                t.save(update_fields=["fix_evidence", "updated_at"])
                AuditLog.objects.create(
                    actor=user,
                    action="ticket.remind",
                    ticket=t,
                    entity="VulnTicket",
                    entity_id=str(t.pk),
                    diff_json={"reminded_to": to[0]},
                    ip_addr=str(request.META.get("REMOTE_ADDR", "")),
                )
        return Response(
            {
                "requested": len(id_list),
                "sent_emails": sent_emails,
                "reminded_tickets": reminded,
                "skipped_cooldown": skipped_cooldown,
                "skipped_unassigned": skipped_unassigned,
            }
        )


class _ManualCreateError(Exception):
    """400-class input problem for POST /api/ops/tickets (detail, status)."""

    def __init__(
        self,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.extra = extra or {}


def _manual_ip(data: dict[str, Any]) -> str:
    ip = str(data.get("ip", "") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise _ManualCreateError(f"非法IP：{ip}") from None
    return ip


def _manual_port(data: dict[str, Any]) -> int:
    try:
        port = int(str(data.get("port", 443) or 443))
    except (TypeError, ValueError):
        raise _ManualCreateError("端口需为数字") from None
    if not 1 <= port <= 65535:
        raise _ManualCreateError("端口需在 1-65535 之间")
    return port


def _manual_severity(data: dict[str, Any]) -> str:
    severity = str(data.get("severity", "") or "").strip()
    if severity not in SEVERITY_VALUES:
        raise _ManualCreateError(
            f"非法严重性：{severity}", extra={"allowed": SEVERITY_VALUES}
        )
    return severity


def _manual_title_cve(data: dict[str, Any]) -> tuple[str, str]:
    title = str(data.get("title", "") or data.get("plugin_name", "") or "").strip()
    cve = str(data.get("cve", "") or "").strip()
    if not title and not cve:
        raise _ManualCreateError("缺少标题（title 或 CVE 至少填一个）")
    return title, cve


def _manual_cvss(data: dict[str, Any]) -> float | None:
    if data.get("cvss") in (None, ""):
        return None
    try:
        cvss = float(str(data.get("cvss")))
    except (TypeError, ValueError):
        raise _ManualCreateError("CVSS 需为数字") from None
    if not 0 <= cvss <= 10:
        raise _ManualCreateError("CVSS 需在 0-10 之间")
    return cvss


def _manual_source(data: dict[str, Any]) -> str:
    source = str(data.get("source", "") or "").strip()
    if len(source) > 64:
        raise _ManualCreateError("来源最多64个字符")
    return source


def _manual_batch(source_text: str) -> ScanBatch:
    """Shared MANUAL batch for a source label (reused on repeat).

    Empty text -> the shared "手工录入" batch; custom text -> its own
    batch keyed by manual-sha256(text). Displayed via source_label.
    """
    if source_text:
        file_hash = "manual-" + hashlib.sha256(source_text.encode()).hexdigest()[:32]
        batch, _ = ScanBatch.objects.get_or_create(
            file_hash=file_hash,
            defaults={"file_name": source_text, "source": BatchSource.MANUAL},
        )
        return batch
    batch, _ = ScanBatch.objects.get_or_create(
        file_hash="manual-entry",
        defaults={"file_name": "手工录入", "source": BatchSource.MANUAL},
    )
    return batch


def _manual_target(data: dict[str, Any], ip: str) -> User | None:
    username = str(data.get("assignee", "") or "").strip()
    if not username:
        return get_current_owner(ip)
    target: User | None = User.objects.filter(username=username).first()
    if target is None or not target.is_active:
        raise _ManualCreateError(
            f"用户不存在或已停用：{username}", status.HTTP_404_NOT_FOUND
        )
    if target.role == Role.AUDITOR:
        raise _ManualCreateError("审计员不可作为处理人", HTTP_UNPROCESSABLE)
    return target


class OpsTicketCreateView(APIView):
    """POST /api/ops/tickets (operator only, manual entry for third-party findings).

    Body: {ip*, port=443, protocol=tcp|udp, severity*, title*, cve?,
    description?, solution?, cvss?, assignee?, source?}. ``title`` lands in
    plugin_name (ticket_title falls back plugin_name -> cve -> ip:port).
    ``source`` is free text (e.g. 安恒渗透测试/HW/威胁情报, max 64 chars);
    omitted -> shared "手工录入" batch. Custom text gets its own MANUAL
    ScanBatch (reused on repeat), so 来源 shows the text verbatim.
    assignee is a username (active, non-auditor); omitted -> auto-dispatch
    via the IP's current owner mapping. SLA clock starts at creation
    (compute_due over first_seen, independent of assignment). Assigned
    tickets move straight to 待修复 via transition(); ownerless ones stay
    待分配 in the orphan pool. -> 201 detail.
    """

    permission_classes = [IsOperator]

    def post(self, request: Request) -> Response:
        user: User = _actor(request)
        data: dict[str, Any] = request.data if isinstance(request.data, dict) else {}
        protocol = str(data.get("protocol", "tcp") or "tcp").strip().lower()
        if protocol not in ("tcp", "udp"):
            return Response(
                {"detail": "protocol 仅支持 tcp/udp"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            ip = _manual_ip(data)
            port = _manual_port(data)
            severity = _manual_severity(data)
            title, cve = _manual_title_cve(data)
            cvss = _manual_cvss(data)
            source_text = _manual_source(data)
            target = _manual_target(data, ip)
        except _ManualCreateError as exc:
            return Response(
                {"detail": exc.detail, **exc.extra}, status=exc.status_code
            )
        now = timezone.now()
        batch = _manual_batch(source_text)
        ticket = VulnTicket(
            dedup_key=uuid.uuid4().hex,
            ip=ip,
            port=port,
            protocol=protocol,
            plugin_name=title,
            cve=cve,
            severity=severity,
            cvss=cvss,
            description=str(data.get("description", "") or ""),
            solution=str(data.get("solution", "") or ""),
            state=TicketState.PENDING_ASSIGN,
            sla_due_at=compute_due(now, severity),
            first_seen_at=now,
            last_seen_at=now,
            batch=batch,
            assignee=target,
        )
        ticket.save()
        if target is not None:
            try:
                ticket = transition(
                    ticket, TicketState.PENDING_FIX, actor_role=user.role, payload={}
                )
            except DjangoValidationError as exc:
                return Response(
                    {"detail": "; ".join(exc.messages)},
                    status=HTTP_UNPROCESSABLE,
                )
            except PermissionDenied as exc:
                return Response(
                    {"detail": str(exc) or "forbidden"},
                    status=status.HTTP_403_FORBIDDEN,
                )
            refreshed: VulnTicket = VulnTicket.objects.get(pk=ticket.pk)
        else:
            refreshed = VulnTicket.objects.get(pk=ticket.pk)
        return Response(VulnTicketDetailSerializer(refreshed).data, status=status.HTTP_201_CREATED)


class _TicketEditError(Exception):
    """400-class input problem for PATCH /api/ops/:id/edit."""

    def __init__(
        self,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.extra = extra or {}


def _edit_title(ticket: VulnTicket, data: dict[str, Any], changed: dict[str, dict[str, Any]]) -> None:
    if "title" not in data:
        return
    title = str(data.get("title") or "").strip()
    if not title:
        raise _TicketEditError("标题不可为空")
    if ticket.plugin_name != title:
        changed["plugin_name"] = {"old": ticket.plugin_name, "new": title}
        ticket.plugin_name = title


def _edit_severity(ticket: VulnTicket, data: dict[str, Any], changed: dict[str, dict[str, Any]]) -> None:
    if "severity" not in data:
        return
    severity = str(data.get("severity") or "").strip()
    if severity not in SEVERITY_VALUES:
        raise _TicketEditError(
            f"非法严重性：{severity}", extra={"allowed": SEVERITY_VALUES}
        )
    if ticket.severity != severity:
        changed["severity"] = {"old": ticket.severity, "new": severity}
        ticket.severity = severity


def _edit_text(
    ticket: VulnTicket, data: dict[str, Any],
    changed: dict[str, dict[str, Any]], field: str,
) -> None:
    if field not in data:
        return
    value = str(data.get(field) or "")
    old = str(getattr(ticket, field) or "")
    if old != value:
        changed[field] = {"old": old, "new": value}
        setattr(ticket, field, value)


def _edit_cve(ticket: VulnTicket, data: dict[str, Any], changed: dict[str, dict[str, Any]]) -> None:
    if "cve" not in data:
        return
    cve = str(data.get("cve") or "").strip()
    if len(cve) > 64:
        raise _TicketEditError("CVE 最多64个字符")
    if ticket.cve != cve:
        changed["cve"] = {"old": ticket.cve, "new": cve}
        ticket.cve = cve


def _edit_cvss(ticket: VulnTicket, data: dict[str, Any], changed: dict[str, dict[str, Any]]) -> None:
    if "cvss" not in data:
        return
    raw_cvss = data.get("cvss")
    cvss: float | None = None
    if raw_cvss not in (None, ""):
        try:
            cvss = float(str(raw_cvss))
        except (TypeError, ValueError):
            raise _TicketEditError("CVSS 需为数字") from None
        if not 0 <= cvss <= 10:
            raise _TicketEditError("CVSS 需在 0-10 之间")
    if ticket.cvss != cvss:
        changed["cvss"] = {"old": ticket.cvss, "new": cvss}
        ticket.cvss = cvss


def _edit_source(ticket: VulnTicket, data: dict[str, Any], changed: dict[str, dict[str, Any]]) -> None:
    if "source" not in data:
        return
    source = str(data.get("source") or "").strip()
    if len(source) > 64:
        raise _TicketEditError("来源最多64个字符")
    if not source:
        return
    old_label = source_label(ticket)
    if old_label == source:
        return
    ticket.batch = _manual_batch(source)
    changed["source"] = {"old": old_label, "new": source}


class OpsTicketEditView(APIView):
    """PATCH /api/ops/:id/edit (operator only, post-creation content fix).

    Body (all optional, at least one): {title, severity, description,
    solution, cve, cvss, source}. ``title`` writes plugin_name. IP/port are
    immutable (reassign ownership instead) -> 400 if present.
    ``source`` switches the ticket to the MANUAL batch of that label
    (reused on repeat); empty/missing leaves the batch untouched.
    Closed/ignored tickets -> 422. Severity change recomputes the SLA
    clock from first_seen. Every applied change is written to AuditLog
    as action ticket.update {changed: {field: {old, new}}}. -> 200 detail.
    """

    permission_classes = [IsOperator]

    def patch(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = VulnTicket.objects.filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        if ticket.state in (TicketState.CLOSED, TicketState.IGNORED):
            return Response(
                {"detail": f"已关闭/已忽略的工单不可编辑（当前：{ticket.state}）"},
                status=HTTP_UNPROCESSABLE,
            )
        data: dict[str, Any] = request.data if isinstance(request.data, dict) else {}
        if "ip" in data or "port" in data:
            return Response(
                {"detail": "IP/端口不可修改（如需变更归属请改派或补资产映射）"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        changed: dict[str, dict[str, Any]] = {}
        try:
            _edit_title(ticket, data, changed)
            _edit_severity(ticket, data, changed)
            _edit_text(ticket, data, changed, "description")
            _edit_text(ticket, data, changed, "solution")
            _edit_cve(ticket, data, changed)
            _edit_cvss(ticket, data, changed)
            _edit_source(ticket, data, changed)
        except _TicketEditError as exc:
            return Response(
                {"detail": exc.detail, **exc.extra}, status=exc.status_code
            )
        if not changed:
            return Response(
                {"detail": "无有效修改（可改：title/severity/description/solution/cve/cvss/source）"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if "severity" in changed:
            base = ticket.first_seen_at or timezone.now()
            old_due = ticket.sla_due_at.isoformat() if ticket.sla_due_at else None
            ticket.sla_due_at = compute_due(base, ticket.severity)
            changed["sla_due_at"] = {
                "old": old_due,
                "new": ticket.sla_due_at.isoformat() if ticket.sla_due_at else None,
            }
        ticket.save()
        AuditLog.objects.create(
            actor=user,
            action="ticket.update",
            ticket=ticket,
            entity="VulnTicket",
            entity_id=str(ticket.pk),
            diff_json={"changed": changed},
            ip_addr=str(request.META.get("REMOTE_ADDR", "")),
        )
        refreshed: VulnTicket = VulnTicket.objects.get(pk=ticket.pk)
        return Response(VulnTicketDetailSerializer(refreshed).data)


class OpsTicketDeleteView(APIView):
    """DELETE /api/ops/:id (operator only, testing convenience).

    Hard-deletes the ticket (any state) and cascades to its evidence/
    timeline rows. An AuditLog row (action=ticket.delete, ticket FK is
    SET_NULL so it survives the delete) snapshots {ip, title, state,
    severity} for traceability. -> 200 {deleted, id}; unknown id -> 404.
    """

    permission_classes = [IsOperator]

    def delete(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = VulnTicket.objects.filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        snapshot = {
            "ip": ticket.ip,
            "title": ticket.plugin_name,
            "state": ticket.state,
            "severity": ticket.severity,
        }
        AuditLog.objects.create(
            actor=user,
            action="ticket.delete",
            ticket=ticket,
            entity="VulnTicket",
            entity_id=str(ticket.pk),
            diff_json={"deleted": snapshot},
            ip_addr=str(request.META.get("REMOTE_ADDR", "")),
        )
        ticket.delete()
        return Response({"deleted": True, "id": pk, **snapshot})


class OpsUsersView(APIView):
    """GET /api/ops/users (operator/leader only, assignable users for dispatch)."""

    permission_classes = [IsAuthenticated, IsOperatorOrLeader]

    def get(self, request: Request) -> Response:
        del request
        rows = (
            User.objects.filter(is_active=True)
            .exclude(role=Role.AUDITOR)
            .order_by("dept", "username")
            .values("id", "username", "dept", "role")[:500]
        )
        return Response({"results": list(rows)})


def split_dept(dept: str) -> tuple[str, str | None]:
    """Split '一级/二级/...' into (first, rest-or-None), stripped."""
    parts = [p.strip() for p in str(dept or "").split("/") if p.strip()]
    if not parts:
        return "", None
    first = parts[0]
    rest = "/".join(parts[1:])
    return first, rest or None


class OpsDepartmentsView(APIView):
    """GET /api/ops/departments (operator/leader only, dept cascade data).

    Distinct non-empty User.dept values grouped by first segment:
    {first: [...], tree: {一级: [二级...]}, count}. Powers the pool
    一级/二级 cascade selects; filter via ?dept_prefix= / ?dept=.
    """

    permission_classes = [IsAuthenticated, IsOperatorOrLeader]

    def get(self, request: Request) -> Response:
        del request
        names = (
            User.objects.exclude(dept="")
            .values_list("dept", flat=True)
            .distinct()
        )
        tree: dict[str, list[str]] = {}
        for raw in names:
            first, rest = split_dept(raw)
            if not first:
                continue
            bucket = tree.setdefault(first, [])
            if rest is not None and rest not in bucket:
                bucket.append(rest)
        for bucket in tree.values():
            bucket.sort()
        ordered = dict(sorted(tree.items()))
        return Response(
            {"first": list(ordered), "tree": ordered, "count": len(ordered)}
        )


class UserAdminView(APIView):
    """Operator user management (IsOperator only).

    GET /api/ops/admin/users?q=&role=&active= -> paginated user rows
    POST /api/ops/admin/users {username*, dept, email, role, wecom_userid,
        password?} -> create (temp password returned once when absent)
    """

    permission_classes = [IsOperator]

    def get(self, request: Request) -> Response:
        qs: QuerySet[User] = User.objects.order_by("username")
        q: str = str(request.query_params.get("q", "") or "").strip()
        if q:
            qs = qs.filter(username__icontains=q)
        role: str = str(request.query_params.get("role", "") or "").strip()
        if role:
            qs = qs.filter(role=role)
        active: str = str(request.query_params.get("active", "") or "").strip().lower()
        if active in ("true", "1"):
            qs = qs.filter(is_active=True)
        elif active in ("false", "0"):
            qs = qs.filter(is_active=False)
        page = max(int(request.query_params.get("page", 1) or 1), 1)
        page_size = min(max(int(request.query_params.get("page_size", 20) or 20), 1), 100)
        total = qs.count()
        rows = list(
            qs[(page - 1) * page_size : page * page_size].values(
                "id", "username", "dept", "email", "role", "wecom_userid",
                "is_active", "last_login",
            )
        )
        return Response({"results": rows, "count": total})

    def post(self, request: Request) -> Response:
        from django.utils.crypto import get_random_string

        username: str = str(request.data.get("username", "") or "").strip()
        if not username:
            return Response({"detail": "缺少 username"}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=username).exists():
            return Response(
                {"detail": f"用户已存在：{username}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        role: str = str(request.data.get("role", "") or Role.OWNER).strip()
        if role not in (Role.OWNER, Role.LEADER, Role.OPERATOR, Role.AUDITOR):
            return Response({"detail": f"非法角色：{role}"}, status=status.HTTP_400_BAD_REQUEST)
        password: str = str(request.data.get("password", "") or "")
        generated = ""
        if not password:
            generated = get_random_string(12)
            password = generated
        user = User(
            username=username,
            role=role,
            is_active=True,
            dept=str(request.data.get("dept", "") or ""),
            email=str(request.data.get("email", "") or ""),
            wecom_userid=str(request.data.get("wecom_userid", "") or "") or None,
        )
        user.set_password(password)
        user.save()
        AuditLog.objects.create(
            actor=request.user if isinstance(request.user, User) else None,
            action="user.create",
            entity="User",
            entity_id=str(user.username),
            diff_json={"role": user.role},
            ip_addr=str(request.META.get("REMOTE_ADDR", "")),
        )
        body: dict[str, Any] = {
            "id": user.pk, "username": user.username, "dept": user.dept,
            "email": user.email, "role": user.role,
            "wecom_userid": user.wecom_userid, "is_active": user.is_active,
        }
        if generated:
            body["temp_password"] = generated
        return Response(body, status=status.HTTP_201_CREATED)


class UserAdminDetailView(APIView):
    """PATCH /api/ops/admin/users/:username {email, dept, wecom_userid, role,
    is_active} + POST .../reset-password {password?} (IsOperator only)."""

    permission_classes = [IsOperator]

    def _target(self, username: str) -> User | None:
        return User.objects.filter(username=username).first()

    def _user_audit(
        self, request: Request, action: str, target: User, diff: dict[str, Any]
    ) -> None:
        actor = request.user if isinstance(request.user, User) else None
        AuditLog.objects.create(
            actor=actor,
            action=action,
            entity="User",
            entity_id=str(target.username),
            diff_json=diff,
            ip_addr=str(request.META.get("REMOTE_ADDR", "")),
        )

    def _apply_profile(self, user: User, data: dict[str, Any]) -> Response | None:
        if "email" in data:
            user.email = str(data.get("email") or "")
        if "dept" in data:
            user.dept = str(data.get("dept") or "")
        if "wecom_userid" in data:
            raw = str(data.get("wecom_userid") or "").strip()
            if raw and User.objects.filter(wecom_userid=raw).exclude(pk=user.pk).exists():
                return Response(
                    {"detail": f"企微账号已被占用：{raw}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.wecom_userid = raw or None
        if "role" in data:
            role = str(data.get("role") or "").strip()
            if role not in (Role.OWNER, Role.LEADER, Role.OPERATOR, Role.AUDITOR):
                return Response({"detail": f"非法角色：{role}"}, status=status.HTTP_400_BAD_REQUEST)
            user.role = role
        return None

    def _deactivation_intent(
        self, request: Request, user: User, data: dict[str, Any]
    ) -> tuple[bool, Response | None]:
        if "is_active" not in data:
            return False, None
        new_active = bool(data.get("is_active"))
        if not new_active and user.pk == request.user.pk:
            return False, Response({"detail": "不能停用自己的账号"}, status=status.HTTP_400_BAD_REQUEST)
        actor = request.user
        actor_role = str(getattr(actor, "role", "") or "")
        if not new_active and user.role == Role.ADMIN and actor_role != Role.ADMIN:
            return False, Response(
                {"detail": "仅管理员可停用管理员账号"}, status=status.HTTP_403_FORBIDDEN
            )
        deactivated_now = user.is_active and not new_active
        user.is_active = new_active
        return deactivated_now, None

    def _unassign_open_tickets(self, user: User) -> int:
        count = 0
        for t in VulnTicket.objects.filter(assignee=user).exclude(
            state__in=[TicketState.CLOSED, TicketState.IGNORED]
        ):
            t.assignee = None
            t.save()
            count += 1
        return count

    def patch(self, request: Request, username: str) -> Response:
        user = self._target(username)
        if user is None:
            return Response({"detail": "用户不存在"}, status=status.HTTP_404_NOT_FOUND)
        data = request.data
        err = self._apply_profile(user, data)
        if err is not None:
            return err
        deactivated_now, err = self._deactivation_intent(request, user, data)
        if err is not None:
            return err
        user.save()
        unassigned = self._unassign_open_tickets(user) if deactivated_now else 0
        if deactivated_now:
            self._user_audit(
                request, "user.deactivate", user, {"unassigned_open_tickets": unassigned}
            )
        body: dict[str, Any] = {
            "id": user.pk, "username": user.username, "dept": user.dept,
            "email": user.email, "role": user.role,
            "wecom_userid": user.wecom_userid, "is_active": user.is_active,
        }
        if deactivated_now:
            body["unassigned_open_tickets"] = unassigned
        return Response(body)

    def post(self, request: Request, username: str) -> Response:
        from django.utils.crypto import get_random_string

        user = self._target(username)
        if user is None:
            return Response({"detail": "用户不存在"}, status=status.HTTP_404_NOT_FOUND)
        actor = request.user
        if user.role == Role.ADMIN and str(getattr(actor, "role", "") or "") != Role.ADMIN:
            return Response(
                {"detail": "仅管理员可重置管理员密码"}, status=status.HTTP_403_FORBIDDEN
            )
        password: str = str(request.data.get("password", "") or "")
        generated = ""
        if not password:
            generated = get_random_string(12)
            password = generated
        user.set_password(password)
        user.save(update_fields=["password"])
        self._user_audit(request, "user.reset_password", user, {})
        body: dict[str, Any] = {"username": user.username, "reset": True}
        if generated:
            body["temp_password"] = generated
        return Response(body)

    def delete(self, request: Request, username: str) -> Response:
        """DELETE /api/ops/admin/users/:username (IsOperator, testing convenience).

        Hard-deletes the user. VulnTicket.assignee / AuditLog.actor are
        SET_NULL so their tickets fall back to the unassigned pool and the
        audit trail survives; AssetOwnerMap / DeptLeaderMap rows cascade
        (their IPs become ownerless). Guards: cannot delete yourself (400),
        only admin may delete an admin (403). -> 200
        {deleted, username, unassigned_open_tickets}.
        """
        user = self._target(username)
        if user is None:
            return Response({"detail": "用户不存在"}, status=status.HTTP_404_NOT_FOUND)
        if user.pk == request.user.pk:
            return Response({"detail": "不能删除自己的账号"}, status=status.HTTP_400_BAD_REQUEST)
        if user.role == Role.ADMIN and str(getattr(request.user, "role", "") or "") != Role.ADMIN:
            return Response({"detail": "仅管理员可删除管理员账号"}, status=status.HTTP_403_FORBIDDEN)
        unassigned = VulnTicket.objects.filter(assignee=user).exclude(
            state__in=[TicketState.CLOSED, TicketState.IGNORED]
        ).count()
        self._user_audit(
            request,
            "user.delete",
            user,
            {"username": user.username, "role": user.role, "dept": user.dept,
             "unassigned_open_tickets": unassigned},
        )
        user.delete()
        return Response(
            {"deleted": True, "username": username, "unassigned_open_tickets": unassigned}
        )


class OpsPoolView(generics.ListAPIView):
    """GET /api/ops/pool?orphan=&unassigned=&state= (operator/leader only)."""

    permission_classes = [IsAuthenticated, IsOperatorOrLeader]
    serializer_class = VulnTicketListSerializer
    pagination_class = StandardPagination

    def get_queryset(self) -> QuerySet[VulnTicket]:
        qs: QuerySet[VulnTicket] = VulnTicket.objects.select_related("assignee", "batch").order_by(
            "-updated_at", "-id"
        )
        params: dict[str, str] = {k: v for k, v in self.request.query_params.items()}
        try:
            return apply_pool_filters(qs, params)
        except FilterValidationError as exc:
            from rest_framework.exceptions import ValidationError as DRFValidationError

            raise DRFValidationError({"detail": exc.detail, "allowed": exc.allowed}) from exc


EXPORT_MAX_ROWS: int = 10000


class OpsPoolExportView(APIView):
    """GET /api/ops/pool/export?<pool filters> (operator/leader only).

    CSV with UTF-8 BOM (Excel-friendly) of the filtered pool, capped at
    EXPORT_MAX_ROWS; same filters as OpsPoolView via apply_pool_filters.
    """

    permission_classes = [IsAuthenticated, IsOperatorOrLeader]

    def get(self, request: Request) -> Response | HttpResponse:
        qs: QuerySet[VulnTicket] = VulnTicket.objects.select_related("assignee", "batch").order_by(
            "-updated_at", "-id"
        )
        params: dict[str, str] = {k: v for k, v in request.query_params.items()}
        try:
            qs = apply_pool_filters(qs, params)
        except FilterValidationError as exc:
            return Response(
                {"detail": exc.detail, "allowed": exc.allowed},
                status=status.HTTP_400_BAD_REQUEST,
            )
        buf = StringIO()
        _write_ticket_csv_rows(csv.writer(buf), qs, EXPORT_MAX_ROWS)
        resp = HttpResponse("\ufeff" + buf.getvalue(), content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = 'attachment; filename="pool_export.csv"'
        return resp


def _parse_batch_ids(raw_ids: object) -> tuple[list[int], str | None]:
    if not isinstance(raw_ids, list) or not raw_ids:
        return [], "缺少 ids（工单ID列表）"
    if len(raw_ids) > 500:
        return [], "单次最多派500条"
    ids: list[int] = []
    for raw in raw_ids:
        try:
            ids.append(int(raw))
        except (TypeError, ValueError):
            return [], f"非法工单ID：{raw!r}"
    return ids, None


def _assign_single(ticket: VulnTicket, target: User, actor_role: str) -> str | None:
    """Assign one ticket; returns a skip reason when the ticket can't move."""
    if ticket.state in (TicketState.CLOSED, TicketState.IGNORED):
        return f"状态{ticket.state}不可派单"
    ticket.assignee = target
    if ticket.state == TicketState.PENDING_ASSIGN:
        ticket.save(update_fields=["assignee", "updated_at"])
        try:
            transition(ticket, TicketState.PENDING_FIX, actor_role, {})
        except (DjangoValidationError, PermissionDenied) as exc:
            return str(exc)
        return None
    ticket.save()
    return None


class OpsBatchAssignView(APIView):
    """POST /api/ops/batch-assign {ids: [int], assignee} (operator only).

    Same rules as OpsAssignView per ticket: 待分配 -> 待修复 via transition(),
    other open states reassigned in place; closed/ignored reported as
    skipped. Per-ticket mail is suppressed (one summary mail instead);
    cap 500 ids per call.
    """

    permission_classes = [IsOperator]

    def post(self, request: Request) -> Response:
        user: User = _actor(request)
        ids, err = _parse_batch_ids(request.data.get("ids"))
        if err is not None:
            return Response({"detail": err}, status=status.HTTP_400_BAD_REQUEST)
        username = str(request.data.get("assignee", "") or "").strip()
        if not username:
            return Response({"detail": "缺少 assignee（用户名）"}, status=status.HTTP_400_BAD_REQUEST)
        target: User | None = User.objects.filter(username=username).first()
        if target is None or not target.is_active:
            return Response(
                {"detail": f"用户不存在或已停用：{username}"},
                status=status.HTTP_404_NOT_FOUND,
            )
        if target.role == Role.AUDITOR:
            return Response({"detail": "审计员不可作为处理人"}, status=HTTP_UNPROCESSABLE)
        assigned = 0
        skipped: list[dict[str, Any]] = []
        for ticket in VulnTicket.objects.filter(pk__in=ids):
            reason = _assign_single(ticket, target, user.role)
            if reason is None:
                assigned += 1
            else:
                skipped.append({"id": ticket.pk, "reason": reason})
        return Response({"assigned": assigned, "skipped": skipped})


def _batch_transition(
    ids: list[int], to_state: str, actor_role: str, payload: dict[str, Any]
) -> tuple[int, list[dict[str, Any]]]:
    """Apply transition() per ticket; illegal edges become skip reasons."""
    done = 0
    skipped: list[dict[str, Any]] = []
    for ticket in VulnTicket.objects.filter(pk__in=ids):
        try:
            transition(ticket, to_state, actor_role, dict(payload))
        except (DjangoValidationError, PermissionDenied) as exc:
            skipped.append({"id": ticket.pk, "reason": str(exc) or "不可流转"})
        else:
            done += 1
    return done, skipped


class OpsBatchCloseView(APIView):
    """POST /api/ops/batch-close {ids: [int], note?} (operator only).

    待复测→已闭合 per ticket via transition(); other states reported as
    skipped (same shape as batch-assign). Cap 500 ids per call.
    """

    permission_classes = [IsOperator]

    def post(self, request: Request) -> Response:
        user: User = _actor(request)
        ids, err = _parse_batch_ids(request.data.get("ids"))
        if err is not None:
            return Response({"detail": err}, status=status.HTTP_400_BAD_REQUEST)
        note: str = str(request.data.get("note", "") or "")
        closed, skipped = _batch_transition(ids, TicketState.CLOSED, user.role, {})
        if note:
            for ticket_id in [t.pk for t in VulnTicket.objects.filter(pk__in=ids, state=TicketState.CLOSED)]:
                _remember_note(ticket_id, "close_note", note)
        return Response({"closed": closed, "skipped": skipped})


class OpsBatchIgnoreView(APIView):
    """POST /api/ops/batch-ignore {ids: [int], reason*} (operator only).

    Missing reason -> 422 (same rule as single ignore); per-ticket illegal
    edges reported as skipped. Cap 500 ids per call.
    """

    permission_classes = [IsOperator]

    def post(self, request: Request) -> Response:
        user: User = _actor(request)
        ids, err = _parse_batch_ids(request.data.get("ids"))
        if err is not None:
            return Response({"detail": err}, status=status.HTTP_400_BAD_REQUEST)
        reason: str = str(request.data.get("reason", "") or "").strip()
        if not reason:
            return Response({"detail": "忽略原因必填"}, status=HTTP_UNPROCESSABLE)
        ignored, skipped = _batch_transition(
            ids, TicketState.IGNORED, user.role, {"reason": reason}
        )
        return Response({"ignored": ignored, "skipped": skipped})


class OpsCloseView(APIView):
    """POST /api/ops/:id/close {note} (operator only -> 已闭合)."""

    permission_classes = [IsOperator]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = VulnTicket.objects.filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        form = NoteInputSerializer(data=request.data)
        if not form.is_valid():
            return Response(form.errors, status=HTTP_UNPROCESSABLE)
        resp: Response = _transition_response(ticket, TicketState.CLOSED, user.role, {})
        if resp.status_code == 200:
            _remember_note(ticket.pk, "close_note", str(form.validated_data.get("note", "")))
            refreshed: VulnTicket = VulnTicket.objects.get(pk=ticket.pk)
            return Response(VulnTicketDetailSerializer(refreshed).data)
        return resp


class OpsRejectView(APIView):
    """POST /api/ops/:id/reject {note} (operator, 待复测→待修复打回)."""

    permission_classes = [IsOperator]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = VulnTicket.objects.filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        form = NoteInputSerializer(data=request.data)
        if not form.is_valid():
            return Response(form.errors, status=HTTP_UNPROCESSABLE)
        payload: dict[str, Any] = {}
        note: str = str(form.validated_data.get("note", ""))
        if note:
            payload["reject_reason"] = note
        resp: Response = _transition_response(ticket, TicketState.PENDING_FIX, user.role, payload)
        return resp


class OpsIgnoreView(APIView):
    """POST /api/ops/:id/ignore {reason, expires_at} (operator -> 已忽略)."""

    permission_classes = [IsOperator]

    def post(self, request: Request, pk: int) -> Response:
        user: User = _actor(request)
        ticket: VulnTicket | None = VulnTicket.objects.filter(pk=pk).first()
        if ticket is None:
            return Response({"detail": "工单不存在"}, status=status.HTTP_404_NOT_FOUND)
        form = IgnoreInputSerializer(data=request.data)
        if not form.is_valid():
            return Response(form.errors, status=HTTP_UNPROCESSABLE)
        payload: dict[str, Any] = {"reason": str(form.validated_data["reason"])}
        resp: Response = _transition_response(ticket, TicketState.IGNORED, user.role, payload)
        if resp.status_code == 200 and form.validated_data.get("expires_at") is not None:
            expires: datetime = form.validated_data["expires_at"]
            _remember_note(ticket.pk, "ignore_expires_at", expires.isoformat())
            refreshed: VulnTicket = VulnTicket.objects.get(pk=ticket.pk)
            return Response(VulnTicketDetailSerializer(refreshed).data)
        return resp


class DashboardView(APIView):
    """GET /api/dashboard?dept=&dept_prefix= — counts computed live.

    ?dept= exact-matches assignee dept (kept for compatibility);
    ?dept_prefix= prefix-matches (一级部门 filter, e.g. "研发中心" matches
    "研发中心/一组"). ``by_dept`` groups by the top-level dept segment of
    the assignee (dept.split('/')[0]; unassigned -> "未分配").
    """

    permission_classes = [IsAuthenticated, IsAuditorReadOnly]

    @staticmethod
    def _top_dept(dept: object) -> str:
        raw = str(dept or "").strip()
        if not raw:
            return "未分配"
        return raw.split("/")[0].strip() or "未分配"

    def get(self, request: Request) -> Response:
        user: User = _actor(request)
        qs: QuerySet[VulnTicket] = get_visible_tickets(user)
        dept: str = str(request.query_params.get("dept", "") or "").strip()
        if dept:
            qs = qs.filter(assignee__dept=dept)
        dept_prefix: str = str(request.query_params.get("dept_prefix", "") or "").strip()
        if dept_prefix:
            qs = qs.filter(assignee__dept__startswith=dept_prefix)
        now = timezone.now()
        horizon = now + timezone.timedelta(days=AT_RISK_DAYS)
        total: int = qs.count()
        by_state: dict[str, int] = dict.fromkeys(STATE_VALUES, 0)
        for row in qs.values("state").annotate(n=Count("id")):
            by_state[str(row["state"])] = int(row["n"])
        by_severity: dict[str, int] = dict.fromkeys(SEVERITY_VALUES, 0)
        for row in qs.values("severity").annotate(n=Count("id")):
            by_severity[str(row["severity"])] = int(row["n"])
        open_qs: QuerySet[VulnTicket] = qs.filter(state__in=OPEN_STATES)
        overdue: int = open_qs.filter(sla_due_at__lt=now).count()
        at_risk: int = open_qs.filter(sla_due_at__gte=now, sla_due_at__lte=horizon).count()
        ok: int = open_qs.filter(sla_due_at__gt=horizon).count()
        no_due: int = total - overdue - at_risk - ok

        state_rows = (
            qs.exclude(assignee__isnull=True)
            .values("assignee__dept", "state")
            .annotate(n=Count("id"))
        )
        by_dept: dict[str, dict[str, int]] = {}
        for row in state_rows:
            bucket = by_dept.setdefault(
                self._top_dept(row["assignee__dept"]),
                {"total": 0, "open": 0, "closed": 0, "overdue": 0},
            )
            n = int(row["n"])
            bucket["total"] += n
            if row["state"] in OPEN_STATES:
                bucket["open"] += n
            else:
                bucket["closed"] += n
        unassigned_total = qs.filter(assignee__isnull=True).count()
        if unassigned_total:
            by_dept["未分配"] = {
                "total": unassigned_total,
                "open": unassigned_total,
                "closed": 0,
                "overdue": 0,
            }
        overdue_rows = (
            qs.exclude(assignee__isnull=True)
            .filter(state__in=OPEN_STATES, sla_due_at__lt=now)
            .values("assignee__dept")
            .annotate(n=Count("id"))
        )
        for row in overdue_rows:
            by_dept.setdefault(
                self._top_dept(row["assignee__dept"]),
                {"total": 0, "open": 0, "closed": 0, "overdue": 0},
            )["overdue"] = int(row["n"])

        return Response(
            {
                "total": total,
                "by_state": by_state,
                "by_severity": by_severity,
                "sla": {"overdue": overdue, "at_risk": at_risk, "ok": ok, "no_due": no_due},
                "by_dept": dict(sorted(by_dept.items(), key=lambda kv: -kv[1]["total"])),
            },
            status=status.HTTP_200_OK,
        )


class SlaPolicyView(APIView):
    """SLA policy admin (admin role only).

    GET /api/ops/sla-policies -> {results: [{severity, days,
    warn_days_before, source}]} merged over the 7/30/90/180 fallback.
    PUT /api/ops/sla-policies/<severity> {days, warn_days_before?} ->
    upsert; takes effect on next compute_due (new tickets + reopen) and
    on escalation warn windows.
    """

    permission_classes = [IsAuthenticated, IsAdminRole]
    _VALID: frozenset[str] = frozenset(FALLBACK_SLA_DAYS)

    def get(self, request: Request) -> Response:
        del request
        table = {p.severity: p for p in SlaPolicy.objects.all()}
        results = [
            {
                "severity": severity,
                "days": table[severity].days if severity in table else fallback_days,
                "warn_days_before": (
                    table[severity].warn_days_before if severity in table else 3
                ),
                "source": "table" if severity in table else "fallback",
            }
            for severity, fallback_days in FALLBACK_SLA_DAYS.items()
        ]
        return Response({"results": results})

    def put(self, request: Request, severity: str) -> Response:
        if severity not in self._VALID:
            return Response(
                {"detail": f"非法严重性：{severity}", "allowed": sorted(self._VALID)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        days = request.data.get("days")
        warn = request.data.get("warn_days_before", None)
        if not isinstance(days, int) or not 1 <= days <= 365:
            return Response(
                {"detail": "days 需为 1-365 的整数"}, status=status.HTTP_400_BAD_REQUEST
            )
        if warn is not None and (not isinstance(warn, int) or not 0 <= warn <= 60):
            return Response(
                {"detail": "warn_days_before 需为 0-60 的整数"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        policy, _created = SlaPolicy.objects.update_or_create(
            severity=severity,
            defaults={"days": days, "warn_days_before": int(warn) if warn is not None else 3},
        )
        return Response(
            {
                "severity": policy.severity,
                "days": policy.days,
                "warn_days_before": policy.warn_days_before,
                "source": "table",
            }
        )


class AuditListView(generics.ListAPIView):
    """GET /api/audit?ticket_id=&actor= (admin/operator/auditor, read-only)."""

    permission_classes = [IsAuthenticated, IsAuditViewer]
    serializer_class = AuditLogSerializer
    pagination_class = StandardPagination

    def get_queryset(self) -> QuerySet[AuditLog]:
        qs: QuerySet[AuditLog] = AuditLog.objects.select_related("actor", "ticket").order_by(
            "-created_at", "-id"
        )
        params = self.request.query_params
        ticket_id: str = str(params.get("ticket_id", "") or "").strip()
        if ticket_id:
            if not ticket_id.isdigit():
                from rest_framework.exceptions import ValidationError as DRFValidationError

                raise DRFValidationError({"detail": f"非法ticket_id：{ticket_id}"})
            qs = qs.filter(ticket_id=int(ticket_id))
        actor_q: str = str(params.get("actor", "") or "").strip()
        if actor_q:
            cond: Q = Q(actor__username__icontains=actor_q)
            if actor_q.isdigit():
                cond = cond | Q(actor_id=int(actor_q))
            qs = qs.filter(cond)
        return qs
