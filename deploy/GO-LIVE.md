# 业务上线准备清单（GO-LIVE）

> `deploy/README.md` 讲「怎么跑起来」，本文讲「跑起来之前要准备什么、之后要做什么」。
> 逐条打勾后再 `docker compose up -d`。标注 ⛔ 的为阻断项，不解决不能上线。
> **不用 Docker？** 看 [BARE-METAL.md](./BARE-METAL.md)（方案说明）与
> [BARE-METAL-RUNBOOK.md](./BARE-METAL-RUNBOOK.md)（全新 24.04 服务器一步到位执行手册），
> 本文档的密钥/业务初始化/备份/验收清单全部通用。

---

## 0. 前端构建变量（已在 Dockerfile.web / docker-compose.yml 修复注入）

> 背景：`import.meta.env` 是**构建期**烘焙进 JS 产物的，不是运行时读取。
> 此前镜像构建不传 VITE 变量导致两个坑：API 地址固化成 `http://localhost:8000`
> （阻断）、企微扫码参数缺失。现已通过 `Dockerfile.web` 的
> `ARG VITE_API_BASE / VITE_WECOM_CORPID / VITE_WECOM_AGENTID` +
> `docker-compose.yml` 的 `web.build.args`（从 `deploy/.env` 透传）修复，
> 构建产物已验证：同源 `''` 正确烘焙、企微参数按 `.env` 注入。

| 变量 | 留空行为 | 什么时候填 |
|---|---|---|
| `VITE_API_BASE` | 同源 `/api` 走 nginx（推荐，默认留空） | 仅当 API 与页面**不同源**部署时 |
| `VITE_WECOM_CORPID` / `VITE_WECOM_AGENTID` | 登录页显示「企微扫码接入中」，走本地账号+TOTP | 拿到企微自建应用参数后填入并 `docker compose build web` |

在 `deploy/.env` 里设置，之后 `docker compose build web`（改构建变量必须重建
镜像，运行时改不生效）。企微可信域名需备案域名，纯内网 IP 过不了校验——
这种部署就保持留空，日常走本地账号 + TOTP（见 §3）。

---

## 1. 基础设施准备

| 项 | 要求 |
|---|---|
| 主机 | Ubuntu 22.04/24.04，`docker compose version` 可用（Compose v2）；单机全容器化，2C/4G/50G 磁盘起步即可 |
| 代码位置 | 仓库检出如 `/opt/vuln-ticket`（compose build 上下文是相对路径，别挪） |
| 域名 | 内网 DNS 解析一条（如 `vuln.internal.example.com`）→ 填 `DJANGO_ALLOWED_HOSTS`（⛔必填，不允许 `*`，为空 compose 直接拒启） |
| 端口规划 | 对外仅 **80**（web）；**21 + 40000-40100/tcp**（FTP，防火墙务必只放行 RSAS 扫描器来源 IP）。5432/6379/8000 全部不对外 |
| 数据卷 | compose 自动建 6 个：`db-data` `redis-data` `rsas-drop` `watcher-state` `cmdb-cursor` `media-data`；备份只关心 `db-data` 和 `media-data`（见 §7） |

## 2. 密钥与 `.env`（⛔）

```bash
cd deploy && cp .env.example .env && chmod 600 .env
```
必填项（缺失 compose 会 fail-fast 拒启）：

| 变量 | 生成/说明 |
|---|---|
| `POSTGRES_PASSWORD` | `openssl rand -base64 24` |
| `DJANGO_SECRET_KEY` | `openssl rand -base64 40`，与 JWT 密钥不同 |
| `JWT_SECRET_KEY` | `openssl rand -base64 32` |
| `DJANGO_ALLOWED_HOSTS` | 真实内网域名或 IP，逗号分隔 |
| `FTP_USER` / `FTP_PASS` | 给 RSAS 扫描器投递用，`FTP_PASS` ≥20 字符 |
| `PASV_ADDRESS` | **本机内网 IP**（绝不填 127.0.0.1，否则 PASV 数据连接全挂） |
| `WATCHER_TOKEN` | 见下方 ⚠️ 专述 |
| 条件项 | `WECOM_SECRET`（要扫码登录才填）、`CMDB_TOKEN`（要 CMDB 同步才填） |

⚠️ **WATCHER_TOKEN 有效期陷阱**：它是某个运营账号的 JWT，而 `watch.py` 只带
静态 Bearer、**不会刷新**；默认 `JWT_ACCESS_MINUTES=60` 意味着 **1 小时后
FTP 投递管线整体 403**。两个方案二选一：
1.（推荐，内网工具）`JWT_ACCESS_MINUTES=43200`（30 天）+ `JWT_REFRESH_DAYS=90`，
   全局放宽——内网系统可接受，换 token 频率降到每月；
2. 保持 60 分钟，用 cron 每小时调 `/api/auth/local` 换新 JWT 写回 .env（改造 watcher 支持 refresh 是更干净的长期方案）。

签发：先按 §5 建好 `svc_watcher`（operator 角色）账号，用其账密调
`POST /api/auth/local` 取 `jwt` 填入。

## 3. 企微侧准备（要扫码登录/群通知才做）

- 企业微信管理后台 → 自建应用：记下 **CorpID**（企业ID）、**AgentID**、**Secret**
- 应用「网页授权及 JS-SDK 可信域名」填部署域名（⚠️ 需备案域名，内网 IP 过不了；
  过不了就放弃扫码，走本地账号+TOTP，见 §0.2）
- 通讯录权限：应用可见范围覆盖全部需要登录的员工（导入按姓名(工号)对上企微账号）
- 群机器人：目标告警群 → 添加机器人 → 复制 **webhook 地址**（部署后在页面配置）

## 4. SMTP / CMDB 准备

- **SMTP**（派单/复测/关闭/SLA 升级邮件）：企业邮箱账号+授权码，如
  `smtp.exmail.qq.com:465 SSL`。可先只在 `.env` 填，也可上线后页面改。
- **CMDB**（可选，小时级同步资产）：`CMDB_BASE_URL` + `CMDB_TOKEN`。
- 以上全部支持**部署后在「系统配置(/ops/config) 集成中心」页面修改，立即生效、
  无需重启**（页面值优先于 env；密钥留空=保持不变）。

## 5. 首次启动（有序执行）

```bash
cd /opt/vuln-ticket/deploy
docker compose up -d --build          # db/redis 健康检查通过后 api 才起
docker compose exec api python manage.py migrate    # ⛔ 不会自动跑，必须手动
docker compose exec api python manage.py collectstatic   # 可选：Django admin 样式
```

**创建首个管理员**（⛔ `createsuperuser` 建出来的角色默认是 owner，不是系统管理员，
必须用下面方式直接指定 role）：
```bash
docker compose exec api python manage.py shell -c "
from apps.accounts.models import User
u = User(username='admin', role='admin', is_active=True, dept='安全运营')
u.set_password('改成强密码')
u.save()
print('admin created')"
```
登录 `/` → 右上角进 `/mfa` 开启 TOTP（本地登录二次验证）。SLA 四档策略
由迁移自动种子（0002），在 `/ops/config` 核对天数即可。

**验收**：浏览器开 `http://<域名>` → 登录 → `/ops/config` 集成中心各卡
「发送测试」通过；`GET /api/auth/me` 带 token 返回当前用户。

## 6. 业务数据初始化

按顺序：
1. **资产汇总表导入**（/ops/imports/assets）：上传**完整**的《服务器资源汇总表.xlsx》。
   ⚠️ 汇总表格式是**全量同步**：表里没有的 IP 会被置无主、部门负责人映射按新表
   重建——永远传全量表，不要传挑出来的子集。Dry-Run 先看 `orphaned_preview`。
   导入自动建号（owner/leader，临时密码只显示一次，转交本人）。
2. **负责人邮箱表导入**（同页第二张卡）：列 `负责人(姓名(工号))或工号 + 邮箱`，
   只更新已有账号（邮件通知依赖它）。
3. **用户管理**（/ops/users）：补建运营账号（operator），核对 leader/owner 名单、
   让本人登录改密 + 开 TOTP。

## 7. RSAS 扫描器对接

1. 扫描器「报告 FTP 自动上传」指向 `PASV_ADDRESS:21`，账号 `FTP_USER/FTP_PASS`。
2. watcher 默认 `WATCHER_DRY_RUN=true`（只预览零写库）：先跑 1-2 天，在
   `/imports` 批次列表确认解析正常，再改 `.env` `WATCHER_DRY_RUN=false`
   并 `docker compose up -d watcher` 正式入库。
3. 状态文件 `watcher-state` 已传过的 zip 不会重传；API 侧 file_hash 双保险。

## 8. 备份与运维

```bash
# 数据库每日备份（crontab）
0 2 * * * docker compose -f /opt/vuln-ticket/deploy/docker-compose.yml exec -T db \
  pg_dump -U vuln vulntickets | gzip > /backup/vulntickets-$(date +\%F).sql.gz
# 证据图卷（media-data）每周 tar 一次；恢复必须演练过一次才算就绪
```
- 升级流程：`git pull` → `docker compose build` → `docker compose exec api python manage.py migrate` → `docker compose up -d`
- 排障：`docker compose logs -f api worker beat watcher`；登录失败锁定看 `.env` 的 `LOGIN_*`
- 不要动 `watcher-state`/`cmdb-cursor` 卷（可重建但会造成重传/全量同步）

## 9. 上线验收清单

- [ ] `.env` 全部必填项已填，无 CHANGE_ME 残留，`chmod 600`
- [ ] `DJANGO_DEBUG=false`、`DJANGO_ALLOWED_HOSTS` 为真实域名
- [ ] §0 构建变量确认：登录后任意页面 API 请求走同源 `/api`（F12 Network 确认，无 localhost:8000）
- [ ] migrate 已执行；首个 admin（role=admin）可登录，TOTP 已开启
- [ ] 汇总表全量导入成功，`/ops/assets` 部门资产总览可见、部门负责人能登录
- [ ] 邮箱表已导入；集成中心 SMTP「发送测试」收到邮件
- [ ] 企微群机器人「发送测试」进群（如启用）
- [ ] FTP 投递 dry-run 批次出现在 `/imports`，随后切 `WATCHER_DRY_RUN=false`
- [ ] 手工建一张测试工单 → 派单 → 提交 → 复测 → 关闭全流程走通
- [ ] pg_dump 备份任务已挂 cron，恢复演练做过一次
- [ ] 防火墙：仅 80 / 21 / 40000-40100 对应来源开放
