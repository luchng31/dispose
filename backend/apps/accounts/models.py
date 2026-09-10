from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.TextChoices):
    ADMIN = "admin", "管理员"
    OPERATOR = "operator", "运营"
    LEADER = "leader", "负责人审批"
    OWNER = "owner", "资产负责人"
    AUDITOR = "auditor", "审计只读"


class User(AbstractUser):
    # Nullable: users without WeCom (local-only) share NULL, which never
    # collides under UNIQUE (unlike blank "" which would).
    wecom_userid: str | None = models.CharField(
        max_length=64, unique=True, null=True, blank=True, default=None
    )
    dept: str = models.CharField(max_length=128, blank=True, default="")
    role: str = models.CharField(max_length=16, choices=Role.choices, default=Role.OWNER)
    # base32 TOTP seed; blank means MFA disabled for this user.
    totp_secret: str = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        db_table = "user"
        verbose_name = "用户"
        verbose_name_plural = "用户"
        indexes = [
            models.Index(fields=["dept"]),
        ]

    def __str__(self) -> str:
        return f"{self.username}({self.wecom_userid})"


class DeptLeaderMap(models.Model):
    """部门负责人 ↔ 部门路径映射（资产导入时按「部门负责人/资源使用部门」列写入）。

    一个负责人可管辖多条部门路径（含兄弟子树，见服务器资源汇总表），
    因此用显式映射而非 User.dept 前缀推导；查询侧按
    Asset.biz_system ∈ user 的 dept_path 集合裁剪可见资产。
    """

    user: User = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="dept_leader_maps"
    )
    dept_path: str = models.CharField(max_length=255)
    created_at: models.DateTimeField = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "dept_leader_map"
        verbose_name = "部门负责人映射"
        verbose_name_plural = "部门负责人映射"
        constraints = [
            models.UniqueConstraint(fields=["user", "dept_path"], name="uniq_user_dept_path")
        ]
        indexes = [
            models.Index(fields=["dept_path"]),
        ]

    def __str__(self) -> str:
        return f"{self.user_id} leads {self.dept_path}"
