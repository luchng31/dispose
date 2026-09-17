# 用户批量清理手册（保留指定账号，删除其余）

> 场景：测试/演示后清空业务账号，只保留管理员和系统账号（如 `admin`、`svc_watcher`）。
> 方法：Django shell 脚本直删（不走 API，免登录、无数量限制），先预览后执行。
> 本文命令在**服务器上以 root 执行**，示例路径 `/opt/vuln-ticket`。

## 0. 原理与安全性

| 关联数据 | 删用户时的行为 |
|---|---|
| 名下在办工单 | 脚本**先**把 assignee 置空（进待分配/无主池），工单本身保留 |
| 资产映射 AssetOwnerMap | 外键 CASCADE，随用户消失 → 相关 IP 变无主 |
| 部门负责人映射 DeptLeaderMap | CASCADE，随用户消失 |
| 审计日志 AuditLog.actor | SET_NULL，日志保留（操作人变空） |
| 附件 TicketAttachment.uploaded_by | SET_NULL，附件保留 |

- 删除整体包在 `transaction.atomic()` 里：中途任何报错**全部回滚**，不会删一半。
- `KEEP` 集合就是白名单，想多留账号往里加用户名即可。
- 审计不可恢复；若要连工单/资产一起清空，见文末「与业务清库的组合」。

## 1. 登录并写预览脚本（只看不删）

```bash
ssh root@172.16.0.50

cat > /tmp/list_users.py <<'EOF'
from apps.accounts.models import User
from apps.tickets.models import VulnTicket

KEEP = {"admin", "svc_watcher"}   # 要保留的账号，按需改
for u in User.objects.exclude(username__in=KEEP):
    print(u.pk, u.username, u.role,
          "owned_tickets:", VulnTicket.objects.filter(assignee=u).count())
print("将删除:", User.objects.exclude(username__in=KEEP).count(),
      "将保留:", User.objects.filter(username__in=KEEP).count())
EOF
```

运行预览：

```bash
sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py shell < /tmp/list_users.py'
```

**核对**「将删除」的数量和名单，确认没有误留/误删。

## 2. 执行删除

```bash
cat > /tmp/del_users.py <<'EOF'
from apps.accounts.models import User, DeptLeaderMap
from apps.tickets.models import VulnTicket
from apps.assets.models import AssetOwnerMap
from django.db import transaction

KEEP = {"admin", "svc_watcher"}
qs = User.objects.exclude(username__in=KEEP)
with transaction.atomic():
    # 1) 先退回这些人的在办工单（不删工单，负责人置空 → 进待分配/无主池）
    n = VulnTicket.objects.exclude(assignee=None) \
        .exclude(assignee__username__in=KEEP).update(assignee=None)
    print("tickets auto-unassigned:", n)
    print("before: users=%d maps=%d dept_maps=%d" % (
        User.objects.count(),
        AssetOwnerMap.objects.filter(valid_to=None).count(),
        DeptLeaderMap.objects.count(),
    ))
    # 2) 删除用户；资产映射/部门负责人映射随外键级联清除
    print("deleted:", qs.delete())
    print("after: users=%d maps=%d dept_maps=%d" % (
        User.objects.count(),
        AssetOwnerMap.objects.filter(valid_to=None).count(),
        DeptLeaderMap.objects.count(),
    ))
    print("kept:", list(User.objects.values_list("username", "role")))
EOF
sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py shell < /tmp/del_users.py'
```

输出会依次给出：退回工单数、删除前后用户/映射数、最终保留名单。

## 3. 清理临时脚本

```bash
rm -f /tmp/list_users.py /tmp/del_users.py
```

## 4. 验证

```bash
# 最终账号应只剩 KEEP 里的
sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py shell -c "
from apps.accounts.models import User
print([(u.username, u.role, u.is_active) for u in User.objects.all()])
"'
```

- 平台界面：用户管理页应只剩白名单账号；无主资产/待分配池出现对应数据属正常。
- FTP 管线：`svc_watcher` 在白名单内则不受影响（无需重签 token）。

## 5. 与业务清库的组合

只删用户不清业务数据时，工单/批次/审计仍在。若想连业务数据一起清空
（工单+附件+延期申请、扫描批次、审计、资产+映射），按此顺序在 shell 里执行：

```python
from apps.tickets.models import VulnTicket, TicketAttachment, DelayRequest
from apps.imports.models import ScanBatch
from apps.assets.models import Asset, AssetOwnerMap
from apps.accounts.models import DeptLeaderMap
from apps.audit.models import AuditLog
for m in (DelayRequest, TicketAttachment, VulnTicket, ScanBatch, AuditLog,
          AssetOwnerMap, DeptLeaderMap, Asset):
    print(m.__name__, m.objects.all().delete())
```

证据图片在磁盘上：`rm -rf /opt/vuln-ticket/backend/media/*`。
保留项：用户账号、SLA 策略、集成配置（sysconfig）、`.env`。

## 6. 注意事项

- **白名单优先**：先跑预览再删，名单以预览输出为准。
- **svc_watcher 必须保留**（或删后重签 WATCHER_TOKEN，见 FTP-SETUP.md §3），否则 FTP 自动投递 401。
- 导入汇总表可随时重建用户/映射（`姓名(工号)` 自动建号，临时密码仅导入结果页显示一次）。
