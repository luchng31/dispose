# FTP 自动投递配置（RSAS 扫描器 → 自动入库）

> 场景：裸机部署（`/opt/vuln-ticket`，如 `root@172.16.0.50`），让绿盟 RSAS
> 扫描完自动把报告 ZIP 投进 FTP，系统轮询入库，批次来源标注「漏洞扫描」。
> 链路：**RSAS 控制台 →(FTP 21/PASV)→ /srv/rsas-drop →(watcher 15s 轮询)
> → POST /api/imports/rsas?source=ftp → 批次 + 自动派单**。
> 不想配也能用：`/imports` 页面手工传 ZIP（dry-run、file_hash 去重、来源标注全都有）。

本文所有命令在**服务器上以 root 执行**（`ssh root@172.16.0.50`）。
示例 IP `172.16.0.50` 请替换为你服务器的**实际内网 IP**。

---

## 0. 前提检查

```bash
ls /opt/vuln-ticket/backend/manage.py        # 已部署
systemctl is-active vuln-api                  # active
getent passwd vuln                            # vuln 用户存在
sudo install -d -o vuln -g vuln /var/lib/vuln-watcher   # watcher 状态目录（已存在则跳过）
```

## 1. FTP 账号与目录

```bash
useradd -r -m -d /srv/rsas-drop -s /usr/sbin/nologin rsas
passwd rsas        # 设置 FTP 密码
chmod 755 /srv/rsas-drop   # Ubuntu 24.04 家目录默认可能 0700，vuln 用户要能读
apt install -y vsftpd

# ⚠️ 必做：Ubuntu 的 vsftpd 认证链含 pam_shells 检查，shell 不在 /etc/shells
# 里的用户无论密码对错一律 530 拒登——必须把 nologin 加进去：
grep -qx /usr/sbin/nologin /etc/shells || echo /usr/sbin/nologin >> /etc/shells
```

- `/srv/rsas-drop` 就是投递目录：扫描器上传的 ZIP 落这里，watcher 从这里取。
- `rsas` 是系统账号、禁止 shell 登录，只能走 FTP。

## 2. vsftpd 配置（关键：pasv_address）

`/etc/vsftpd.conf` 整体替换为：

```ini
listen=YES
listen_ipv6=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
local_umask=022
check_shell=NO
pasv_enable=YES
pasv_address=172.16.0.50
pasv_min_port=40000
pasv_max_port=40100
```

⚠️ `pasv_address` 必须是**本机内网 IP**，绝不能写 `127.0.0.1`——
否则扫描器的 PASV 数据连接全部失败（登录成功但传不了文件）。

```bash
systemctl restart vsftpd

# 防火墙：只放行扫描器来源 IP（21 命令通道 + 40000-40100 数据通道）
ufw allow from <扫描器IP> to any port 21 proto tcp
ufw allow from <扫描器IP> to any port 40000:40100 proto tcp
```

本地自测：`ftp 127.0.0.1`（账号 rsas）→ `put 一个测试.zip` → `ls /srv/rsas-drop` 能看到。

## 3. watcher 专用账号与 token（⚠️ 有效期陷阱）

watcher 调导入接口需要一个**运营角色的 JWT**。JWT 默认 60 分钟过期且不会自动
刷新——先把全局有效期调到 30 天，再签发：

```bash
grep -q '^JWT_ACCESS_MINUTES' /opt/vuln-ticket/.env && \
  sed -i 's/^JWT_ACCESS_MINUTES=.*/JWT_ACCESS_MINUTES=43200/' /opt/vuln-ticket/.env || \
  echo 'JWT_ACCESS_MINUTES=43200' >> /opt/vuln-ticket/.env
systemctl restart vuln-api

# 建专用运营账号（只用来签 token，不给人用；密码换成强密码）
sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py shell -c "
from apps.accounts.models import User
u, created = User.objects.get_or_create(username=\"svc_watcher\", defaults={\"role\": \"operator\", \"is_active\": True, \"dept\": \"系统账号\"})
u.set_password(\"换成强密码\")
u.save()
print(\"svc_watcher ready\")"'

# 签发 30 天 JWT 并写入 .env
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/local -H 'Content-Type: application/json' \
  -d '{"username":"svc_watcher","password":"换成强密码"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['jwt'])")
grep -q '^WATCHER_TOKEN=' /opt/vuln-ticket/.env && \
  sed -i "s|^WATCHER_TOKEN=.*|WATCHER_TOKEN=${TOKEN}|" /opt/vuln-ticket/.env || \
  echo "WATCHER_TOKEN=${TOKEN}" >> /opt/vuln-ticket/.env
```

svc_watcher 是 operator 角色：能调导入接口，但看不到用户管理/系统配置等 admin 功能，
泄露了也只影响导入面。

## 4. watcher systemd 常驻

`/etc/systemd/system/vuln-watcher.service`：

```ini
[Unit]
Description=vuln-ticket RSAS drop watcher
After=vuln-api.service

[Service]
User=vuln
Group=vuln
EnvironmentFile=/opt/vuln-ticket/.env
Environment=API_BASE=http://127.0.0.1:8000
Environment=WATCH_DIR=/srv/rsas-drop
Environment=STATE_FILE=/var/lib/vuln-watcher/seen.json
Environment=DRY_RUN=true
ExecStart=/opt/vuln-ticket/.venv/bin/python /opt/vuln-ticket/deploy/watcher/watch.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
chown -R vuln:vuln /var/lib/vuln-watcher
systemctl daemon-reload
systemctl enable --now vuln-watcher
journalctl -u vuln-watcher -n 20        # 应看到 watch-start dir=/srv/rsas-drop dry_run=True
```

说明：
- watch.py 读的环境名是 `DRY_RUN`/`WATCH_DIR` 等（unit 里的 `Environment=` 行），
  `.env` 里的 `WATCHER_DRY_RUN`/`WATCHER_POLL_INTERVAL` 等 FTP_* 变量是 Docker 版
  用的，裸机不生效，留着即可。
- 脚本只用 `requests`，venv 里自带，无需装依赖。
- 轮询间隔默认 15s；文件落盘后等 3 秒大小不再增长才上传（防传一半）。

## 5. RSAS 扫描器侧配置

绿盟 RSAS 控制台 → 系统配置 → 报告自动上传（不同版本入口名称略有差异）：

| 项 | 值 |
|---|---|
| FTP 服务器 | `172.16.0.50`，端口 `21` |
| 账号/密码 | `rsas` / 第 1 步设置的密码 |
| 服务器编码 | `UTF-8`（有默认可留默认；只影响文件名显示，不影响内容） |
| 路径 | `/`（rsas 被 chroot 在 /srv/rsas-drop，**不要**填 /srv/rsas-drop） |
| 被动模式（PASV） | **开启** |
| 上传内容 | 扫描完成后自动上传报告（ZIP） |

## 6. 联调 → 正式切换

1. **预览期**（unit 默认 `DRY_RUN=true`）：让扫描器投 1-2 个报告，
   `journalctl -u vuln-watcher -f` 看到 `uploaded ... counts={...}`；
   `/imports` 页面出现来源「漏洞扫描」的批次、带统计预览，**零写库**。
2. **切换**：确认解析正常后，unit 里改 `DRY_RUN=false`，然后
   `systemctl daemon-reload && systemctl restart vuln-watcher` → 正式入库。
3. FTP 批次的来源列显示「漏洞扫描」；工单按 IP 自动派给现任负责人。

## 7. 日常运维与排错

**投递目录不会自动清理**——watcher 只记录不删除。加个 cron 清旧文件：

```bash
cat > /etc/cron.d/rsas-drop-clean <<'EOF'
# 保留 30 天，每天 03:30 清理已投递的报告 ZIP
30 3 * * * root find /srv/rsas-drop -maxdepth 1 -name '*.zip' -mtime +30 -delete
EOF
```

| 现象 | 原因 | 处理 |
|---|---|---|
| 测试连接 `530 Login incorrect`（密码确认正确） | `pam_shells` 拒绝 nologin shell（见 §1 修复步骤） | `echo /usr/sbin/nologin >> /etc/shells`，即时生效无需重启 |
| 测试连接 `530`，服务器日志见 `pam_unix authentication failure` | 控制台密码与服务端不一致（特殊字符被转码/尾部空格） | 服务器 `passwd rsas` 重置为纯字母数字，控制台重新输入 |
| 扫描器"连接成功但传不了文件" | `pasv_address` 配错（如 127.0.0.1）或 40000-40100 没放行（仅被动模式客户端） | 查 §2；主动模式（PORT）扫描器无此依赖 |
| watcher 日志 `HTTP 401` | WATCHER_TOKEN 过期（默认 30 天） | 重跑 §3 最后一段重新签发，`systemctl restart vuln-watcher` |
| watcher 日志 `watch-dir-unreadable` | 投递目录权限 | `chmod 755 /srv/rsas-drop`（umask 022 上传的文件 644，vuln 可读） |
| 重启后把旧文件又传了一遍 | `seen.json` 被删（在 `/var/lib/vuln-watcher/`） | 无害：API 侧 file_hash 兜底去重，不会产生重复批次/工单 |
| 批次出现但没派单 | 对应 IP 无现任负责人映射 | 去资产管理 → 无主资产补映射，补完会自动重派 |
| 想重导同一个文件 | API 按文件内容 hash 去重，同文件重传返回已有批次 | 改名没用；要真重导需人工处理（慎重） |

## 8. 验证清单

- [ ] `ftp <内网IP>` 用 rsas 账号能登录、能上传
- [ ] `systemctl status vuln-watcher` active，日志有 `watch-start`
- [ ] 投一个测试 ZIP → watcher 日志 `uploaded ... counts={...}`
- [ ] `/imports` 批次列表出现来源「漏洞扫描」的记录
- [ ] （DRY_RUN=false 后）工单池出现新工单，负责人按 IP 映射自动派好
