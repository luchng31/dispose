from __future__ import annotations

import hashlib
from dataclasses import asdict
from typing import Any

from rest_framework import generics, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

try:  # Task2 owns accounts.permissions; fall back to a local stub meanwhile.
    from apps.accounts.permissions import IsOperator  # type: ignore[import-not-found]
except ImportError:  # TODO(Task2): delete stub once accounts/permissions.py lands.
    from rest_framework.permissions import BasePermission

    class IsOperator(BasePermission):
        """Operator-only hook (stub): staff or role in {admin, operator}."""

        message = "operator role required"

        def has_permission(self, request: Request, view: object) -> bool:
            user = request.user
            if not user or not user.is_authenticated:
                return False
            if getattr(user, "is_staff", False):
                return True
            return str(getattr(user, "role", "")) in {"admin", "operator"}


from apps.accounts.models import User
from apps.tickets.views import StandardPagination

from .asset_import import (
    EMAIL_TEMPLATE_HEADER,
    TEMPLATE_HEADER,
    apply_asset_rows,
    apply_owner_email_rows,
    count_sync_orphans,
    is_summary_format,
    normalize_header,
    parse_asset_file,
    parse_owner_email_file,
)
from .mapping import FIELD_MAP_VERSION, load_field_map
from .models import BatchSource, ScanBatch
from .parsers import parse_and_normalize
from .serializers import DryRunResultSerializer, ScanBatchSerializer
from .tasks import dedupe_findings, import_batch, preview_import

MAX_UPLOAD_BYTES = 50 * 1024 * 1024

_DRY_TRUE = frozenset({"1", "true", "yes", "on"})


def _is_dry_run(request: Request) -> bool:
    raw = request.query_params.get("dry_run", "false")
    return str(raw).strip().lower() in _DRY_TRUE


class RsasImportView(APIView):
    """POST /api/imports/rsas?dry_run=true|false (multipart ``file``).

    ``batch_name`` (multipart field or query param, optional): 手工上传的
    来源显示名（缺省=文件名），工单列表/批次列表展示；仅 source=manual 生效。
    ``source=ftp`` 记 FTP 投递渠道。

    dry_run=true -> read-only preview
    ``{new, still_open, fixed_unverified, reopened, errors, skipped,
    file_hash}`` with ZERO db writes. Otherwise the upload is parsed,
    deduped by ``md5(ip|port|plugin_id|cve)`` and reconciled; a repeated
    ``file_hash`` (sha256) returns the stored stats with ``skipped: true``.
    A payload with zero valid rows and only errors -> 400.

    New tickets auto-dispatch by IP owner map: assigned -> 待修复 (stats
    ``auto_assigned``), unmapped -> 待分配 orphan pool. 低危 findings are
    auto-ignored with a retention reason (stats ``low_ignored``; reopen
    from the detail page to bring them back into the workflow).
    """

    permission_classes = [IsOperator]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request: Request) -> Response:
        upload = request.FILES.get("file")
        if upload is None:
            return Response(
                {"detail": "multipart field 'file' is required",
                 "errors": [{"row": "file", "field": "file",
                             "message": "missing upload"}]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if upload.size > MAX_UPLOAD_BYTES:
            return Response(
                {"detail": f"file exceeds {MAX_UPLOAD_BYTES} bytes",
                 "errors": [{"row": "file", "field": "file",
                             "message": "file too large"}]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        data: bytes = upload.read()
        file_hash = hashlib.sha256(data).hexdigest()
        findings, errors = parse_and_normalize(upload.name or "upload", data)
        if not findings and errors:
            return Response(
                {"detail": "no valid rows parsed",
                 "errors": errors, "file_hash": file_hash},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if _is_dry_run(request):
            preview = preview_import(file_hash, findings, errors)
            return Response(DryRunResultSerializer(preview).data)
        existing = ScanBatch.objects.filter(file_hash=file_hash).first()
        if existing is not None:
            return Response(
                {"batch_id": existing.id, "skipped": True,
                 "stats": dict(existing.stats_json or {}),
                 "errors": errors, "file_hash": file_hash}
            )
        source = (
            BatchSource.FTP
            if str(request.query_params.get("source", "")).lower() == "ftp"
            else BatchSource.MANUAL
        )
        # 手工上传可自定义来源显示名（工单列表/批次列表用它，缺省=文件名）；
        # 仅 manual 生效。file_hash 去重不受影响：同内容重传仍返回已有批次。
        data = request.data if isinstance(request.data, dict) else {}
        label = str(
            data.get("batch_name") or request.query_params.get("batch_name") or ""
        ).strip()[:512]
        batch = ScanBatch.objects.create(
            file_name=(
                label
                if (label and source == BatchSource.MANUAL)
                else (upload.name or "upload")
            ),
            file_hash=file_hash,
            source=source,
            rsas_version="",
            uploaded_by=request.user if request.user.is_authenticated else None,
            stats_json={"field_map_version": FIELD_MAP_VERSION,
                        "status": "processing"},
        )
        stats = import_batch.run(
            batch.id, rows=[f.to_dict() for f in dedupe_findings(findings).values()]
        )
        return Response(
            {"batch_id": batch.id, "skipped": False,
             "stats": stats, "file_hash": file_hash},
            status=status.HTTP_201_CREATED,
        )


class BatchListView(generics.ListAPIView):
    """GET /api/imports/batches -> file_hash + stats per batch."""

    permission_classes = [IsOperator]
    queryset = ScanBatch.objects.order_by("-created_at")
    serializer_class = ScanBatchSerializer
    pagination_class = StandardPagination


class AssetTemplateView(APIView):
    """GET /api/imports/assets/template -> CSV 模板表头下载."""

    permission_classes = [IsOperator]

    def get(self, request: Request) -> Response:
        from django.http import HttpResponse

        del request
        resp = HttpResponse(TEMPLATE_HEADER, content_type="text/csv")
        resp["Content-Disposition"] = 'attachment; filename="asset_template.csv"'
        return resp


class OwnerEmailTemplateView(APIView):
    """GET /api/imports/owner-emails/template -> 负责人邮箱表 CSV 模板."""

    permission_classes = [IsOperator]

    def get(self, request: Request) -> Response:
        from django.http import HttpResponse

        del request
        resp = HttpResponse(EMAIL_TEMPLATE_HEADER, content_type="text/csv")
        resp["Content-Disposition"] = 'attachment; filename="owner_email_template.csv"'
        return resp


class AssetImportView(APIView):
    """POST /api/imports/assets?dry_run= (multipart file=, 资产+负责人表).

    服务器资源汇总表格式（.xlsx / .csv，UTF-8/GBK）：
      内网IP*, 管理人*, 管理人-隶属组织, 资源使用部门, 部门负责人
    「姓名(工号)」自动拆分建号；管理人建 owner（dept=管理人-隶属组织），
    部门负责人建/升级 leader 并写「负责人↔资源使用部门」映射。
    汇总表格式为权威全量同步（以最新导入为准）：本表未出现的现任 IP
    映射自动置无主（资产保留、在办工单转无主池），部门负责人映射按
    新表重建；旧格式 ip/hostname/os/... 仅增量更新不触发同步。
    dry_run 额外返回 orphaned_preview。自动建号（临时密码仅返回一次）、
    写映射历史、重派该IP未关闭工单。
    """

    permission_classes = [IsOperator]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request: Request) -> Response:
        upload = request.FILES.get("file")
        if upload is None:
            return Response({"detail": "缺少 file 字段"}, status=status.HTTP_400_BAD_REQUEST)
        if upload.size is not None and upload.size > MAX_UPLOAD_BYTES:
            return Response({"detail": "文件超过 50MB"}, status=status.HTTP_400_BAD_REQUEST)
        rows, errors = parse_asset_file(upload.name or "", upload.read())
        if errors:
            return Response(
                {"valid": 0, "invalid": 0, "errors": errors, "applied": False},
                status=status.HTTP_400_BAD_REQUEST,
            )
        sync = is_summary_format(rows)
        if _is_dry_run(request):
            def _canon(row: dict[str, str]) -> dict[str, str]:
                out: dict[str, str] = {}
                for key, value in row.items():
                    hit = normalize_header(str(key))
                    if hit is not None:
                        out[hit] = str(value or "").strip()
                if not out.get("owner") and out.get("wecom_userid"):
                    out["owner"] = out["wecom_userid"]
                return out

            valid = sum(
                1 for r in rows
                if _canon(r).get("ip") and _canon(r).get("owner")
            )
            body: dict[str, Any] = {
                "valid": valid,
                "invalid": len(rows) - valid,
                "errors": [],
                "applied": False,
                "sync": sync,
                "note": "dry-run：未写库，确认后去掉 dry_run 重传",
            }
            if sync:
                body["orphaned_preview"] = count_sync_orphans(rows)
            return Response(body)
        summary = apply_asset_rows(rows, sync=sync)
        summary["applied"] = True
        summary["sync"] = sync
        code = status.HTTP_201_CREATED if not summary["errors"] else status.HTTP_207_MULTI_STATUS
        return Response(summary, status=code)


class OwnerEmailImportView(APIView):
    """POST /api/imports/owner-emails?dry_run= (multipart file=, 负责人邮箱表).

    列：负责人(姓名(工号))或工号* + 邮箱*（.xlsx/.csv）。仅更新已有账号的
    邮箱（不建号），每次变更写 AuditLog(user.email.import)；匹配不到的
    行进 missing 列表。dry_run=true 只预览 {updated, missing}。
    """

    permission_classes = [IsOperator]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request: Request) -> Response:
        from apps.audit.models import AuditLog

        upload = request.FILES.get("file")
        if upload is None:
            return Response({"detail": "缺少 file 字段"}, status=status.HTTP_400_BAD_REQUEST)
        if upload.size is not None and upload.size > MAX_UPLOAD_BYTES:
            return Response({"detail": "文件超过 50MB"}, status=status.HTTP_400_BAD_REQUEST)
        rows, errors = parse_owner_email_file(upload.name or "", upload.read())
        if errors:
            return Response(
                {"valid": 0, "errors": errors, "applied": False},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if _is_dry_run(request):
            preview = apply_owner_email_rows(rows, commit=False)
            return Response(
                {
                    "total_rows": preview["total_rows"],
                    "updated_preview": preview["updated"],
                    "missing": preview["missing"],
                    "errors": preview["errors"],
                    "applied": False,
                    "note": "dry-run：未写库，确认后去掉 dry_run 重传",
                }
            )
        summary = apply_owner_email_rows(rows)
        for change in summary["changes"]:
            AuditLog.objects.create(
                actor=request.user if isinstance(request.user, User) else None,
                action="user.email.import",
                entity="User",
                entity_id=str(change["username"]),
                diff_json={"email": {"old": change["old"], "new": change["new"]}},
                ip_addr=str(request.META.get("REMOTE_ADDR", "")),
            )
        summary["applied"] = True
        code = (
            status.HTTP_201_CREATED
            if not summary["errors"] and not summary["missing"]
            else status.HTTP_207_MULTI_STATUS
        )
        return Response(summary, status=code)


class FieldMapView(APIView):
    """GET /api/imports/field-map -> {version, mapping} (operator only).

    Read-only viewer for the RSAS field map (apps.imports.mapping): version
    is FIELD_MAP_VERSION and mapping is the FieldMap dataclass serialized
    via dataclasses.asdict. No secrets, no writes.
    """

    permission_classes = [IsAuthenticated, IsOperator]

    def get(self, request: Request) -> Response:
        del request
        return Response({"version": FIELD_MAP_VERSION, "mapping": asdict(load_field_map())})


__all__ = [
    "AssetImportView",
    "AssetTemplateView",
    "BatchListView",
    "FieldMapView",
    "OwnerEmailImportView",
    "OwnerEmailTemplateView",
    "RsasImportView",
]
