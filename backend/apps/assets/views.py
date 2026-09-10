"""Asset mapping + orphan pool reads (Task4).

GET /api/assets/mapping?ip= -> {ip, current, history}: the current-valid
owner plus the full close-and-insert history (front-end AssetMapping timeline).
GET /api/assets/orphans -> assets with no current owner (ops-pool KPI input;
ticket-side orphans are VulnTicket with assignee NULL, Task6 filters).
GET /api/assets/overview?q=&dept= -> role-scoped IP allocation overview
(leader: their DeptLeaderMap dept paths; owner: own IPs; operator/admin: all).

Auth: overview is any authenticated user (scope shrinks rows); mapping/orphans
are operator/leader only (IsAuthenticated + IsOperatorOrLeader).
"""

from __future__ import annotations

import functools
import ipaddress
import operator

from django.db.models import Q
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import DeptLeaderMap, Role, User
from apps.accounts.permissions import IsOperator
from apps.assets.dispatch import dispatch_tickets_for_ip, remap_owner
from apps.assets.models import Asset, AssetLevel, AssetOwnerMap, AssetStatus
from apps.tickets.views import IsOperatorOrLeader, StandardPagination


def _actor(request: Request) -> User:
    user: object = request.user
    assert isinstance(user, User)
    return user


class AssetOverviewView(APIView):
    """GET /api/assets/overview?q=&dept=&page=&page_size= -> paginated,
    role-scoped IP allocation overview.

    Scope (dept visibility, 部门负责人等看到管理的所有 IP):
      leader  -> assets whose biz_system is under one of the caller's
                 DeptLeaderMap dept paths (from the 资源使用部门/部门负责人
                 import columns)
      owner   -> assets the caller currently owns (AssetOwnerMap valid_to NULL)
      admin/operator/auditor -> all assets
    Row: {ip, hostname, dept, owner, owner_dept, dept_leader}. Filters:
    ?q= IP substring, ?dept= biz_system prefix. Pagination follows
    StandardPagination (page_size default 20, max 100); count = total
    matching rows.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        user = _actor(request)
        assets = Asset.objects.all().order_by("ip")
        scope = "all"
        if user.role == Role.LEADER:
            dept_paths = list(
                DeptLeaderMap.objects.filter(user=user).values_list("dept_path", flat=True)
            )
            if not dept_paths:
                return Response({"count": 0, "page": 1, "page_size": 20, "results": []})
            # startswith = org-tree inheritance: leading "A" covers child paths "A-B".
            assets = assets.filter(
                functools.reduce(
                    operator.or_,
                    (Q(biz_system__startswith=p) for p in dept_paths),
                )
            )
            scope = "dept"
        elif user.role == Role.OWNER:
            owned = AssetOwnerMap.objects.filter(user=user, valid_to=None).values("ip")
            assets = assets.filter(ip__in=owned)
            scope = "own"
        q = request.query_params.get("q", "").strip()
        if q:
            assets = assets.filter(ip__icontains=q)
        dept_prefix = request.query_params.get("dept", "").strip()
        if dept_prefix:
            assets = assets.filter(biz_system__startswith=dept_prefix)
        try:
            page = max(1, int(request.query_params.get("page", "1")))
        except ValueError:
            page = 1
        try:
            page_size = int(request.query_params.get("page_size", str(StandardPagination.page_size)))
        except ValueError:
            page_size = StandardPagination.page_size
        page_size = min(max(page_size, 1), StandardPagination.max_page_size)
        total = assets.count()
        rows = list(assets[(page - 1) * page_size:page * page_size])
        current_owners: dict[str, User] = {
            m.ip_id: m.user
            for m in AssetOwnerMap.objects.filter(valid_to=None, ip__in=rows)
            .select_related("user")
            .order_by("id")
        }
        leaders: dict[str, str] = {}
        for m in DeptLeaderMap.objects.filter(
            dept_path__in={a.biz_system for a in rows if a.biz_system}
        ).select_related("user").order_by("id"):
            leaders[m.dept_path] = m.user.username
        results = [
            {
                "ip": a.ip,
                "hostname": a.hostname,
                "dept": a.biz_system,
                "owner": current_owners[a.ip].username if a.ip in current_owners else None,
                "owner_dept": current_owners[a.ip].dept if a.ip in current_owners else "",
                "dept_leader": leaders.get(a.biz_system, ""),
            }
            for a in rows
        ]
        return Response(
            {
                "count": total,
                "scope": scope,
                "page": page,
                "page_size": page_size,
                "results": results,
            }
        )


def _row_to_json(row: AssetOwnerMap) -> dict[str, object]:
    user = row.user
    return {
        "wecom_userid": user.wecom_userid,
        "username": user.username,
        "valid_from": row.valid_from.isoformat() if row.valid_from else None,
        "valid_to": row.valid_to.isoformat() if row.valid_to else None,
    }


class AssetMappingView(APIView):
    permission_classes = [IsAuthenticated, IsOperatorOrLeader]

    def get(self, request: Request) -> Response:
        ip = request.query_params.get("ip", "").strip()
        if not ip:
            return Response(
                {"detail": "query param ?ip= is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            asset = Asset.objects.get(ip=ip)
        except Asset.DoesNotExist:
            return Response(
                {"detail": f"unknown asset {ip}"}, status=status.HTTP_404_NOT_FOUND
            )
        rows = list(
            AssetOwnerMap.objects.filter(ip=asset)
            .select_related("user")
            .order_by("-valid_from")
        )
        current = next((r for r in rows if r.valid_to is None), None)
        return Response(
            {
                "ip": asset.ip,
                "hostname": asset.hostname,
                "current": _row_to_json(current) if current is not None else None,
                "history": [_row_to_json(r) for r in rows],
            },
            status=status.HTTP_200_OK,
        )


class OrphanAssetView(APIView):
    """Assets with no current-valid owner — the orphan pool asset side."""

    permission_classes = [IsAuthenticated, IsOperatorOrLeader]

    def get(self, request: Request) -> Response:
        mapped_ips = AssetOwnerMap.objects.filter(valid_to=None).values("ip")
        orphans = Asset.objects.exclude(ip__in=mapped_ips).order_by("ip")[:200]
        return Response(
            {
                "count": len(orphans),
                "results": [
                    {"ip": a.ip, "hostname": a.hostname, "status": a.status}
                    for a in orphans
                ],
            },
            status=status.HTTP_200_OK,
        )


def _checked_ip(raw: object) -> str | None:
    text: str = str(raw or "").strip().lower()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _resolve_owner(username: object) -> tuple[User | None, str | None]:
    """Resolve an owner username; blank means ownerless. Returns (user, error)."""
    text: str = str(username or "").strip()
    if not text:
        return None, None
    target: User | None = User.objects.filter(username=text).first()
    if target is None or not target.is_active:
        return None, f"用户不存在或已停用：{text}"
    if target.role == Role.AUDITOR:
        return None, "审计员不可作为资产负责人"
    return target, None


class AssetCreateView(APIView):
    """POST /api/assets {ip*, hostname?, os?, biz_system?, level?, owner?} (operator).

    Manual entry for offline/non-CMDB assets. Duplicate ip -> 400. When owner
    is given, open tickets on the IP are redispatched (returns remapped count).
    """

    permission_classes = [IsAuthenticated, IsOperator]

    def post(self, request: Request) -> Response:
        data = request.data
        ip: str | None = _checked_ip(data.get("ip"))
        if ip is None:
            return Response({"detail": "非法IP"}, status=status.HTTP_400_BAD_REQUEST)
        if Asset.objects.filter(ip=ip).exists():
            return Response({"detail": f"资产已存在：{ip}"}, status=status.HTTP_400_BAD_REQUEST)
        level: str = str(data.get("level", "") or "").strip() or AssetLevel.MEDIUM
        if level not in AssetLevel.values:
            return Response(
                {"detail": f"非法等级：{level}", "allowed": list(AssetLevel.values)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        owner, err = _resolve_owner(data.get("owner"))
        if err is not None:
            return Response({"detail": err}, status=status.HTTP_404_NOT_FOUND)
        asset = Asset.objects.create(
            ip=ip,
            hostname=str(data.get("hostname", "") or ""),
            os=str(data.get("os", "") or ""),
            biz_system=str(data.get("biz_system", "") or ""),
            level=level,
            status=AssetStatus.ONLINE,
        )
        remapped = 0
        if owner is not None:
            remap_owner(asset, owner)
            remapped = dispatch_tickets_for_ip(ip)
        return Response(
            {"ip": asset.ip, "hostname": asset.hostname, "owner": owner.username if owner else None,
             "remapped": remapped},
            status=status.HTTP_201_CREATED,
        )


class AssetRemapView(APIView):
    """POST /api/assets/remap {ip*, username?} (operator).

    Blank username closes the current mapping (asset becomes ownerless).
    Open tickets on the IP are redispatched (returns remapped count).
    """

    permission_classes = [IsAuthenticated, IsOperator]

    def post(self, request: Request) -> Response:
        data = request.data
        ip: str | None = _checked_ip(data.get("ip"))
        if ip is None:
            return Response({"detail": "非法IP"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            asset = Asset.objects.get(ip=ip)
        except Asset.DoesNotExist:
            return Response(
                {"detail": f"未知资产：{ip}"}, status=status.HTTP_404_NOT_FOUND
            )
        owner, err = _resolve_owner(data.get("username"))
        if err is not None:
            return Response({"detail": err}, status=status.HTTP_404_NOT_FOUND)
        remap_owner(asset, owner)
        remapped: int = dispatch_tickets_for_ip(ip)
        return Response(
            {"ip": ip, "owner": owner.username if owner else None, "remapped": remapped}
        )
