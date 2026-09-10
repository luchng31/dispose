# 漏洞修复工单系统（一漏一单）

绿盟 RSAS 扫描结果导入 → 按 IP 自动找负责人 → 修复/复测/闭环，
企微扫码登录，管理员本地账号例外。前端企微原生协同风。

技术栈：Django 5 + DRF + PostgreSQL 16 + Redis + Celery /
Vue 3 + Vite + Element Plus。无 drf-spectacular：
**`backend/apps/tickets/urls.py` 的模块 docstring 就是 schema**，改接口必须同步改它；
前端每个 `src/api/*.ts` 函数头的一行 `/** 契约注释 */` 与之对应。

---

## 1. 快速启动

```bash
# 后端（本机无 PG/Redis 时用 sqlite+LocMem 直跑）
cd backend
DB_ENGINE=sqlite python3 manage.py migrate
DB_ENGINE=sqlite python3 manage.py runserver 127.0.0.1:8000 --noreload

# 前端
cd frontend
npm install
npm run dev        # :5173（CORS 白名单只认 5173，preview 换端口会被 403）
```

- 生产：`deploy/.env.example` 复制为 `.env` 填空，`docker-compose.yml` 启动
  （postgres/redis/backend/worker/beat/ftp-watch 等）。
- **改了后端路由/filter/permission，必须 `--noreload` 重启**（autoreload 不可靠）。
- 端口：后端 `:8000`，前端 `:5173`。JWT 存 `localStorage[vuln_jwt]`。
- 演示账号：`admin / Demo1234!`（管理操作账号，本地登录）、
  `demo_operator / Demo1234!`、`real_owner / Real1234!`。

## 2. 功能地图

| 页面 | 路由 | 能做什么 |
|---|---|---|
| 登录 | `/login` | 企微扫码优先（`?code=` 自动换 JWT）；下方"管理员入口"切本地账号+TOTP |
| 我的工单 | `/my` | 状态/严重性/搜索过滤，按 IP 汇总；改密 |
| 工单池（运营） | `/ops` | 全部/无主/未分配/逾期/延期审批 tab；状态+严重性+搜索组合过滤；派单/批量派单/新建工单/关闭/驳回/忽略/导出 CSV |
| 工单详情 | `/my/:id` | 漏洞信息（含发现日期/来源）、描述、修复建议、证据图、证据/审计双时间线、提交证据、申请延期 |
| 资产映射 | `/assets` | 部门资产总览（负责人/资源使用部门/部门负责人，leader 只见管辖部门）、IP↔负责人映射增改查、历史版本、无主资产快捷查看、CMDB 立即同步 |
| 导入管理 | `/imports` | 漏洞报告导入（RSAS ZIP，含 dry-run 预览、批次列表） |
| 资产导入 | `/imports/assets` | 资产汇总表导入（服务器资源汇总表 .xlsx/CSV，**以最新导入为准全量同步**：表外 IP 置无主+部门映射重建，dry-run 预览 orphaned_preview）、负责人邮箱表导入（仅更新已有账号邮箱） |
| 用户管理 | `/ops/users` | 建号（临时密码）、重置密码、启用/停用（停用自动退回其在办工单） |
| 审计 | `/audit` | 全量审计行查询 |
| 系统配置 | `/ops/config` | SLA 策略编辑、看板（含一级部门分布）、**集成中心**、字段映射查看 |

核心规则：

- **一漏一单**：去重键 `md5(ip|port|plugin|cve)`；复扫 reconcile（新增/仍存/已修待验/重开）。
- **状态机**：待分配 --派单--> 待修复 --提交证据--> 待复测 --关闭--> 已闭合；
  待复测 --驳回--> 待修复；待修复 --延期审批--> 已延期 --恢复--> 待修复；
  任意 --忽略--> 已忽略；已闭合/已忽略 --重开--> 待修复（新 SLA）。
  所有流转走 `transition()` 白名单，非法 422。
- **派单**：导入/新建时按 IP 现任负责人自动派（无映射进无主池）；
  手工派单/改派不碰 SLA 时钟；停用用户自动退回其在办工单。
- **无主 ⊂ 未分配**：未分配 = 无负责人；无主 = 无负责人 + IP 无现任映射。
  手工派单后工单同时退出两列；IP 归属缺口去资产管理补映射。
- **来源**：扫描批次渠道（FTP投递/手工上传 zip 名）或手工建单手填文本
  （同名复用同一批次）；发现日期 = RSAS 首次发现时间，SLA 自发现日起算。
- **审计**：工单 save 自动写字段 diff（含操作人中间件）；建号/改密/停用/
  集成改配等手写 `AuditLog` 行，密钥一律记 `****`。
- **通知**：SMTP 邮件（派单/复测/关闭/驳回/SLA 升级）+ 企微群机器人
  （SLA 升级推群）；未配置时静默跳过。

## 3. 接口总表

`POST` body 均为 JSON；`?dry_run=true` 表示只预览不写库。
角色：admin/operator/leader/auditor/owner，owner 行级隔离（只能看自己 IP）。

### 认证 `/api/auth/*`（无需登录：local/wecom 回调）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/auth/local` | `{username, password, totp?}` → `{jwt, refresh_token, user}`，防爆破（默认 10 次锁 15min） |
| POST | `/api/auth/wecom/callback` | `{code}` → 同上（需 `WECOM_CORPID/SECRET`） |
| POST | `/api/auth/refresh` | `{refresh_token}` → 新 jwt |
| POST | `/api/auth/logout` | 登出 |
| GET | `/api/auth/me` | 当前用户 |
| POST | `/api/auth/change-password` | `{old_password, new_password}`（≥8位，返新 JWT） |
| POST | `/api/auth/totp/setup` | 领 TOTP 密钥+二维码 |
| POST | `/api/auth/totp/confirm` | `{code}` 启用 TOTP |
| POST | `/api/auth/totp/disable` | 关闭 TOTP |

### 工单（owner：自己的；写操作：运营系）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/tickets/my?state=&severity=&q=` | 我的工单（q 模糊 IP/插件/CVE） |
| GET/— | `/api/tickets/:id` | 详情（含 timeline/attachments/证据）；owner 越权 404 |
| POST | `/api/tickets/:id/submit` | `{evidence:{note, attachment_ids?}}` 提交修复证据 |
| POST | `/api/tickets/:id/delay` | 延期（`delay_days` ≤30 负责人可批，超 30 天需运营） |
| POST | `/api/tickets/:id/delay-request` | 发起延期申请（待修复 only）→ 201 申请单 |
| POST | `/api/tickets/:id/resume` | 已延期恢复推进 |
| POST | `/api/tickets/:id/attachments` | multipart `file=` 传证据图（png/jpg/gif/webp ≤5MB） |

### 运营池 `/api/ops/*`（operator/leader；特别注明的除外）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/ops/pool?orphan=&unassigned=&state=&severity=&q=` | 工单池分页（severity 非法 400 带 allowed） |
| GET | `/api/ops/pool/export` | 同过滤 CSV（UTF-8 BOM，上限 1 万行，含发现日期/来源列） |
| POST | `/api/ops/tickets` | **手工建单** `{ip*, port=443, protocol, severity*, title*, cve?, description?, solution?, cvss?, assignee?, source?}` → 201；不填处理人按 IP 自动派；来源默认"手工录入" |
| POST | `/api/ops/:id/assign` | `{assignee}` 手工派单/改派（待分配→待修复；已闭合/忽略 422） |
| DELETE | `/api/ops/:id` | **删除工单**（operator，任意状态，测试用；审计记 `ticket.delete`，ticket FK SET_NULL 留 {ip,title,state,severity} 快照） |
| POST | `/api/ops/batch-assign` | `{ids[], assignee}` ≤500，返回 `{assigned, skipped[{id,reason}]}` |
| POST | `/api/ops/batch-close` | 批量关闭 |
| POST | `/api/ops/batch-ignore` | 批量忽略（需原因） |
| POST | `/api/ops/:id/close` | `{note?}` 待复测→已闭合 |
| POST | `/api/ops/:id/reject` | `{note?}` 待复测→待修复 |
| POST | `/api/ops/:id/ignore` | `{reason*, expires_at?}` →已忽略（到期自动重开） |
| GET | `/api/ops/delay-requests?status=` | 延期申请列表 |
| POST | `/api/ops/delay-requests/:id/approve\|reject` | `{note?}` 审批 |
| GET | `/api/ops/users` | 可派单用户（在职非审计，≤500） |
| GET/PUT | `/api/ops/sla-policies[/:severity]` | **admin**：四档 SLA 天数+预警天数，只影响新单/重开单 |
| GET/POST | `/api/ops/admin/users` | **运营系**：用户列表/建号（返临时密码） |
| PATCH/POST | `/api/ops/admin/users/:username` | 改部门/角色/停用（返退回工单数）/重置密码 |
| DELETE | `/api/ops/admin/users/:username` | **删除用户**（operator，测试用；在办工单自动退回、资产/部门映射级联清除、审计 `user.delete` 留痕；不能删自己，删管理员需 admin） |
| GET | `/api/ops/notify/status` | SMTP+企微机器人就绪状态（无密码） |
| POST | `/api/ops/notify/test` | `{to?, channel=mail\|wecom}` 发测试 |
| GET | `/api/ops/integrations` | **admin**：集成配置分组（密钥只返 configured） |
| PUT | `/api/ops/integrations` | **admin**：`{key, value}` 写一条（密钥空=保持，非密钥空=回退 env） |
| POST | `/api/ops/integrations/test` | **admin**：`{key: smtp\|wecom.bot\|wecom.login\|cmdb, to?}` 连通性实测 |

### 看板 / 审计

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/dashboard?dept=&dept_prefix=` | 总量/状态/严重性/SLA/一级部门分布（`by_dept`，无负责人归"未分配"） |
| GET | `/api/audit?...` | 审计行（admin/operator/auditor） |

### 导入 `/api/imports/*`（operator）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/imports/rsas?dry_run=&source=` | multipart `file=`（RSAS XML/ZIP，上限见 `MAX_UPLOAD_BYTES`，`source=ftp` 记 FTP 投递） |
| GET | `/api/imports/batches` | 批次列表（hash+统计） |
| GET | `/api/imports/assets/template` | 资产导入模板表头下载（服务器资源汇总表格式） |
| POST | `/api/imports/assets?dry_run=` | multipart `file=` 资产+负责人导入（.xlsx/.csv）。汇总表格式：内网IP*, 管理人*, 管理人-隶属组织, 资源使用部门, 部门负责人（`姓名(工号)` 自动拆分；管理人建 owner，部门负责人建/升级 leader）。**汇总表格式=权威全量同步**：本表未出现的现任 IP 映射置无主（资产保留、在办工单转无主池）、DeptLeaderMap 按新表重建，dry-run 返回 `orphaned_preview`；旧格式 ip/hostname/os/biz_system/owner/owner_dept/email/wecom_userid 仅增量更新不触发同步（表头支持"工号"别名，仅工号列时兜底作负责人用户名） |
| GET | `/api/imports/owner-emails/template` | 负责人邮箱表 CSV 模板下载（负责人,工号,邮箱） |
| POST | `/api/imports/owner-emails?dry_run=` | multipart `file=` 负责人邮箱表（负责人(姓名(工号))或工号 + 邮箱）。仅更新**已有账号**邮箱（不建号），每笔变更写审计 `user.email.import`，匹配不到的行进 missing（207） |
| GET | `/api/imports/field-map` | RSAS→工单字段映射 `{version, mapping}`（当前版本 2） |

### 资产 / CMDB

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/api/assets/mapping?ip=` | 映射查询/改派（close-and-insert 留历史） |
| GET | `/api/assets/overview?q=&dept=&page=&page_size=` | 角色裁剪的 IP 分配总览（分页，page_size 默认 20 最大 100）：leader=其管辖部门（`dept_leader_map` 前缀匹配）全部 IP，owner=自己名下，运营系=全量；行含 ip/dept/owner/owner_dept/dept_leader，count=命中总数 |
| GET | `/api/assets/orphans` | 无现任负责人的资产（≤200，补映射入口） |
| POST | `/api/assets` | 新建资产 |
| POST | `/api/assets/remap` | 批量重映射（在办同 IP 工单自动跟随改派） |
| POST | `/api/cmdb/sync` | 拉 CMDB 全量增量 → `{upserted, remapped, orphaned}`（失败 502 明文原因） |

## 4. 之后接口怎么接（操作手册）

### 4.1 新增业务接口（标准五步）

1. `backend/apps/<app>/views.py` 写 `XxxView(APIView)`：
   权限用现成的 `IsOperator`（运营写）/`IsOperatorOrLeader`（池读）/
   `IsAdminRole`（配改）/`IsAuthenticated`（登录即可）；
   入参非法 → 400 `{detail, allowed?}`，状态机违规 → 422，越权 → 403/404
   （owner 隔离用 404 避免探存）。
2. 状态变更必须走 `transition()`，禁止手写 `ticket.state =`；
   非 ticket.save 场景的手工审计行仿 `_user_audit` 写法，
   `action="<domain>.<verb>"`，密钥/密码只记 `****`。
3. `backend/apps/tickets/urls.py`（或所属 app 的 `urls.py`）注册路由，
   **并在模块 docstring 补一行契约**（无 swagger，这是唯一 schema）。
4. `backend/apps/tickets/tests/test_api_matrix.py`（或所属 tests）加用例：
   200 主路径 + 403 越权 + 400 非法入参，跑
   `DB_ENGINE=sqlite python3 -m pytest apps/ -q` 全绿 + `ruff check`。
5. 前端 `src/api/<domain>.ts` 加函数（一行 `/** 契约注释 */`），页面调用；
   `npm run build` + `npm test` 全绿。

### 4.2 对接新的外部系统（三步上架到集成中心）

以"新增短信网关"为例，全部仿 SMTP/企微/CMDB 现成做法：

1. 后端取值：一律经 `apps.sysconfig.store.get(key, default)`，
   key 进 `SECRET_KEYS`（密钥）或明文组，env 变量名写进
   `deploy/.env.example`（env = 默认值，页面值优先，**无需重启**）。
   消费者禁止直读 `os.environ`（`apps/accounts/wecom.py` 的 `_env`
   只保留作测试 seam）。
2. 开放改配：`apps/sysconfig/views.py` 的 key 白名单 + 校验分支加新 key，
   `GET` 分组加一组字段；需要"测试连接"就给 `POST .../test` 加一个
   target（只读探活，异常一律 `{ok:false, detail}` 不得 500）。
3. 前端：`src/api/integrations.ts` 加取/存函数，`SysConfig.vue` 加一张卡
   （密钥输入框 placeholder 写"已设置，留空=不修改"，绝不回显）。
   FTP/Watcher 是例外：watcher 是独立容器只认 env，只能在卡片里放
   只读清单 + "改后重启 watcher" 提示。

### 4.3 对接新的扫描器（非 RSAS）

1. `backend/apps/imports/parsers.py` 加解析函数，输出统一
   `NormalizedFinding`（字段见 `mapping.py`：ip/port/plugin/cve/严重性…）。
2. 字段差异只改 `apps/imports/mapping.py` + `field_map.json`，
   并把 `FIELD_MAP_VERSION` 加 1（批次统计里可追溯）。
3. 新来源需要入库统计：`ScanBatch.source` 加 TextChoices 一项；
   列表"来源"显示规则在 `serializers.source_label`（手工类显示批次名）。

### 4.4 定时任务

Celery beat 任务放 `apps/<app>/tasks.py`（仿 `check_sla`/`check_ignore_expiry`），
shared_task 命名 `apps.<app>.tasks.<name>`；需要周期跑的在 deploy 层加
beat schedule（`CELERY_BEAT_SCHEDULE` 注释位）。

## 5. 测试与门禁

```bash
cd backend
DB_ENGINE=sqlite python3 -m pytest apps/ -q   # 全量（约130+，3分钟）
python3 -m ruff check apps/                    # 零错
cd ../frontend
npm test        # vitest，8文件40用例
npm run build   # vue-tsc + vite，绿了才算
```

测试惯例：`_make_user/_auth/_make_ticket` 助手 + `APIClient`；
multipart 用 `SimpleUploadedFile`；owner 行级隔离的断言用 operator 账号；
网络/SMTP 一律 mock；迁移自带的种子数据（如 SLA 四行）先清再测回退。

## 6. 环境变量（`deploy/.env.example` 为准）

| 变量 | 说明 |
|---|---|
| `POSTGRES_*` / `DB_ENGINE=sqlite` | 生产 PG16 / 本机直跑 |
| `DJANGO_SECRET_KEY` / `JWT_SECRET_KEY` / `JWT_ACCESS_MINUTES` / `JWT_REFRESH_DAYS` | 密钥与有效期（无默认值意识，别提交） |
| `WECOM_CORPID` / `WECOM_SECRET` | 扫码登录（后端换 code 用）；前端构建另需 `VITE_WECOM_CORPID` / `VITE_WECOM_AGENTID`（qrConnect 用，构建时 baked） |
| `EMAIL_HOST/PORT/USER/PASSWORD/USE_SSL/USE_TLS` / `DEFAULT_FROM_EMAIL` / `NOTIFY_ENABLED` / `NOTIFY_SUBJECT_PREFIX` | SMTP（页面可覆盖） |
| `NOTIFY_WECOM_WEBHOOK` | 群机器人（页面可覆盖） |
| `CMDB_BASE_URL` / `CMDB_TOKEN` | CMDB 拉取（页面可覆盖） |
| `FTP_*` / `PASV_ADDRESS` / `WATCHER_*` | 报告投递管线（watcher 容器只认 env） |
| `LOGIN_MAX_FAILURES` / `LOGIN_LOCKOUT_SECONDS` | 防爆破 |
| `REDIS_URL` / `CELERY_*` | 缓存与任务（sqlite 下 cache 自动降 LocMem） |

## 7. 约束与坑

- Task1 schema 冻结：不加模型字段，重开计数/升级水位等放 `fix_evidence` JSON。
- 无 `.git`：回退靠手动改回，无版本兜底，大改前先备份文件。
- `GET /api/ops/pool` 非 operator/leader 一律 403；owner 看自己的走 `/my`。
- 已有工单的 SLA 截止时间不受策略修改影响（只影响新单/重开）。
- `batch-close`/`batch-ignore` 已存在但前端暂未接按钮，需要可提。
- TOTP/管理员登录是例外通道，日常只走企微扫码。
