# 全新 Ubuntu 24.04 裸机部署 Runbook（一步到位）

> 适用：一台**全新** Ubuntu 24.04 服务器，从零到可登录使用。
> 与其他文档的关系：方案说明看 [BARE-METAL.md](./BARE-METAL.md)；密钥/企微/SMTP/业务初始化/验收清单看 [GO-LIVE.md](./GO-LIVE.md)——本文是**照着敲**的执行手册。
>
> 占位符：`SERVER_IP` = 服务器 IP（下文用 `hostname -I` 自动取，无需手改）。
> 预计耗时：30-45 分钟。

## 前提

- 服务器：全新 Ubuntu 24.04，`sudo` 权限的登录账号（下文 `ubuntu@SERVER_IP`）
- 开发机：本项目位于 `/home/ubuntu/dispose`（若已有 git 远程仓库，第 3 步可改用 `git clone`，更干净）
- 本次走**最小可用路线**（手工上传 RSAS ZIP，不装 FTP/watcher；要自动化见 [BARE-METAL.md §7](./BARE-METAL.md)）

---

## 0. 系统基础（服务器上）

```bash
sudo apt update && sudo apt upgrade -y
sudo timedatectl set-timezone Asia/Shanghai
# 防火墙：先放行 SSH 再启用，别把自己锁外面
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw --force enable
```

## 1. 装依赖

```bash
sudo apt install -y curl ca-certificates postgresql-16 redis-server nginx python3.12-venv
# Redis 持久化（与 Docker compose 版行为一致）
sudo sed -i 's/^appendonly no/appendonly yes/' /etc/redis/redis.conf
sudo systemctl restart redis-server
# Node 20（前端构建）
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

预期：`psql --version` 显示 16.x，`node -v` 显示 v20.x，`redis-cli ping` 返回 PONG。

## 2. 数据库与系统用户

```bash
# 生成并保存数据库密码（第 4 步会自动读它）
sudo install -m 600 /dev/null /root/vuln-pg-password.txt
sudo sh -c 'openssl rand -hex 16 > /root/vuln-pg-password.txt'
PG_PASSWORD=$(sudo cat /root/vuln-pg-password.txt)

sudo -u postgres psql -c "CREATE USER vuln WITH PASSWORD '$PG_PASSWORD';"
sudo -u postgres psql -c "CREATE DATABASE vulntickets OWNER vuln;"

sudo useradd -r -m -d /opt/vuln-ticket -s /usr/sbin/nologin vuln
sudo install -d -o vuln -g vuln /var/lib/vuln-watcher
sudo mkdir -p /var/www/vuln && sudo chown vuln: /var/www/vuln
```

## 3. 传代码（开发机上执行；rsync 排除运行时数据）

```bash
rsync -a \
  --exclude db.sqlite3 --exclude backend/media --exclude node_modules \
  --exclude dist --exclude __pycache__ --exclude '*.pyc' --exclude .git \
  --exclude .venv --exclude .omo --exclude .opencode --exclude .codegraph \
  --exclude .pytest_cache --exclude .ruff_cache --exclude '*.xlsx' \
  --exclude '*扫描*' --exclude '*.log' \
  /home/ubuntu/dispose/ ubuntu@SERVER_IP:/home/ubuntu/vuln-ticket/
```

服务器上归位：
```bash
sudo mv /home/ubuntu/vuln-ticket /opt/vuln-ticket
sudo chown -R vuln:vuln /opt/vuln-ticket
```

## 4. venv + .env（密钥自动生成，PG 密码自动对齐第 2 步）

```bash
sudo -u vuln python3 -m venv /opt/vuln-ticket/.venv
sudo -u vuln /opt/vuln-ticket/.venv/bin/pip install -r /opt/vuln-ticket/backend/requirements.txt gunicorn==23.0.0

sudo -u vuln cp /opt/vuln-ticket/deploy/.env.example /opt/vuln-ticket/.env

sudo bash -s <<'SCRIPT'
cd /opt/vuln-ticket
IP=$(hostname -I | awk '{print $1}')
PG_PASSWORD=$(cat /root/vuln-pg-password.txt)
sed -i \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PG_PASSWORD}|" \
  -e "s|^DJANGO_SECRET_KEY=.*|DJANGO_SECRET_KEY=$(openssl rand -hex 48)|" \
  -e "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=$(openssl rand -hex 32)|" \
  -e "s|^DJANGO_ALLOWED_HOSTS=.*|DJANGO_ALLOWED_HOSTS=${IP},127.0.0.1,localhost|" \
  -e "s|^FTP_PASS=.*|FTP_PASS=$(openssl rand -hex 12)|" \
  -e "s|^WATCHER_TOKEN=.*|WATCHER_TOKEN=placeholder-not-used|" \
  -e "s|^PASV_ADDRESS=.*|PASV_ADDRESS=${IP}|" .env
chown vuln:vuln .env && chmod 600 .env
grep -nE "^(POSTGRES_PASSWORD|DJANGO_SECRET_KEY|JWT_SECRET_KEY|DJANGO_ALLOWED_HOSTS)" .env
SCRIPT
```

说明：`DJANGO_ALLOWED_HOSTS` 填「本机 IP + 127.0.0.1 + localhost」——本机烟测 curl 走
`127.0.0.1`，Host 头不在白名单会被 Django 直接 400（DisallowedHost）。有内网域名的话
追加到同一行。FTP/watcher 变量走最小路线不生效，留着即可；`WECOM_SECRET/CMDB_TOKEN`
要用时再填。

## 5. 迁移 + 静态文件 + 首个管理员

> ⛔ **手动跑 manage.py 必须先加载 .env**（`set -a; . /opt/vuln-ticket/.env; set +a`）：
> `.env` 只会被 systemd 单元的 `EnvironmentFile=` 自动注入，直接 `sudo -u vuln ... manage.py`
> 是没有这些环境变量的——症状是 `fe_sendauth: no password supplied`。
> 下面三条命令都已带包装，照抄即可。

```bash
sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py migrate'

sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py collectstatic --noinput'

sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py shell -c "
from apps.accounts.models import User
u = User(username=\"admin\", role=\"admin\", is_active=True, dept=\"安全运营\")
u.set_password(\"改成强密码\")
u.save()
print(\"admin created\")"'
```

⛔ **不要用 `createsuperuser`**：建出来的角色默认是 owner，不是系统管理员（IsAdminRole 检查 `role=='admin'`）。SLA 四档策略由迁移 0002 自动种子，无需手配。

## 6. 三个 systemd 服务

```bash
sudo tee /etc/systemd/system/vuln-api.service > /dev/null <<'EOF'
[Unit]
Description=vuln-ticket API (gunicorn)
After=network.target postgresql.service redis-server.service

[Service]
User=vuln
Group=vuln
UMask=0022
WorkingDirectory=/opt/vuln-ticket/backend
EnvironmentFile=/opt/vuln-ticket/.env
ExecStart=/opt/vuln-ticket/.venv/bin/gunicorn config.wsgi:application --bind 127.0.0.1:8000 --workers 3 --timeout 300 --access-logfile -
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/vuln-worker.service > /dev/null <<'EOF'
[Unit]
Description=vuln-ticket Celery worker
After=network.target redis-server.service postgresql.service

[Service]
User=vuln
Group=vuln
UMask=0022
WorkingDirectory=/opt/vuln-ticket/backend
EnvironmentFile=/opt/vuln-ticket/.env
ExecStart=/opt/vuln-ticket/.venv/bin/celery -A config worker --loglevel=INFO --concurrency=2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/vuln-beat.service > /dev/null <<'EOF'
[Unit]
Description=vuln-ticket Celery beat
After=vuln-worker.service

[Service]
User=vuln
Group=vuln
UMask=0022
WorkingDirectory=/opt/vuln-ticket/backend
EnvironmentFile=/opt/vuln-ticket/.env
ExecStart=/opt/vuln-ticket/.venv/bin/celery -A config beat --loglevel=INFO
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vuln-api vuln-worker vuln-beat
systemctl status vuln-api --no-pager | head -5   # 应为 active (running)
```

`UMask=0022` 保证之后上传的证据图对 nginx（www-data）可读。

## 7. 前端构建 + nginx

```bash
cd /opt/vuln-ticket/frontend
sudo -u vuln npm ci
# ⛔ VITE_* 是构建期烘焙：VITE_API_BASE 必须显式置空（=同源 /api），省略变量名
#    会固化成 http://localhost:8000 导致整站不可用。企微参数拿到后填入并重建。
sudo -u vuln env VITE_API_BASE= VITE_WECOM_CORPID= VITE_WECOM_AGENTID= npm run build
sudo -u vuln rsync -a --delete dist/ /var/www/vuln/
```

```bash
sudo tee /etc/nginx/sites-available/vuln > /dev/null <<'EOF'
server {
    listen 80;
    server_name _;
    client_max_body_size 100m;

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_request_buffering off;
    }
    location /admin/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /static/ { alias /opt/vuln-ticket/backend/staticfiles/; }
    location /media/  { alias /opt/vuln-ticket/backend/media/; }
    location / { root /var/www/vuln; index index.html; try_files $uri $uri/ /index.html; }
}
EOF

sudo ln -sf /etc/nginx/sites-available/vuln /etc/nginx/sites-enabled/vuln
sudo rm -f /etc/nginx/sites-enabled/default
# nginx(www-data) 需要穿越 + 读取权限；media 由 Django 首次上传时才懒创建，先建好：
sudo -u vuln mkdir -p /opt/vuln-ticket/backend/media
sudo chmod o+x /opt/vuln-ticket /opt/vuln-ticket/backend
sudo chmod -R o+rX /opt/vuln-ticket/backend/media /opt/vuln-ticket/backend/staticfiles
sudo nginx -t && sudo systemctl reload nginx
```

## 8. 上线烟测

| 检查 | 命令 | 预期 |
|---|---|---|
| 前端页面 | `curl -sI http://127.0.0.1/` | `HTTP/1.1 200` |
| API 直连 | `curl -s http://127.0.0.1:8000/api/auth/me -o /dev/null -w "%{http_code}"` | `403`（未带 token） |
| nginx 反代 | `curl -s http://127.0.0.1/api/auth/me -o /dev/null -w "%{http_code}"` | `403` |
| 服务状态 | `systemctl status vuln-api vuln-worker vuln-beat --no-pager` | 全部 active (running) |

浏览器开 `http://SERVER_IP` → admin 登录 → 右上角 `/mfa` 开启 TOTP。
有内网域名的话：解析后把 `.env` 的 `DJANGO_ALLOWED_HOSTS` 换成域名，
`sudo systemctl restart vuln-api`，浏览器改用域名访问。

## 9. 备份 cron（必做）

```bash
sudo crontab -e   # 追加一行：
0 2 * * * sudo -u postgres pg_dump vulntickets | gzip > /var/backups/vulntickets-$(date +\%F).sql.gz
```
证据图 `/opt/vuln-ticket/backend/media/` 每周 tar 一次；**恢复演练做过一次才算就绪**。

## 10. 后续

- **业务初始化**（GO-LIVE.md §6）：全量导入《服务器资源汇总表》→ 导入负责人邮箱表 → 建运营账号。
  ⚠️ 汇总表格式是**全量同步**：只传完整的新版表，传子集会把表外 IP 置无主。
- **RSAS 自动投递**（可选）：vsftpd + watch.py 的 systemd 跑法见 [BARE-METAL.md §7](./BARE-METAL.md)。
- **排障**：`journalctl -u vuln-api -f`（worker/beat 同理）；登录锁定参数见 `.env` 的 `LOGIN_*`。
- **升级**：`git pull` →（依赖变了才）`pip install -r requirements.txt` → 按 §5 包装命令跑 `migrate` → 前端重新 build+rsync → `sudo systemctl restart vuln-api vuln-worker vuln-beat` → reload nginx。升级前先 `pip freeze > ~/pip-freeze-backup.txt` 留回滚快照。
- **完整验收**：GO-LIVE.md §9 清单逐项打勾（docker 命令按 [BARE-METAL.md §8](./BARE-METAL.md) 对照替换）。

## 常见坑速查

| 症状 | 原因 |
|---|---|
| `fe_sendauth: no password supplied` | 手动跑 manage.py 没加载 `.env`——用 §5 的包装命令（`set -a; . .env; set +a`） |
| `password authentication failed` | `.env` 的 POSTGRES_PASSWORD 与建库密码不一致：对照 `/root/vuln-pg-password.txt` |
| 页面开了但数据全打不开，浏览器请求 `localhost:8000` | 前端构建时没显式置空 `VITE_API_BASE`（§7 重新 build） |
| `createsuperuser` 登录后没有运营权限 | 建出来角色是 owner；必须按 §5 指定 `role='admin'` |
| 502 | vuln-api 没起来：`journalctl -u vuln-api -e`，常见是 `.env` 没填/PG 密码不一致 |
| `DisallowedHost` | `DJANGO_ALLOWED_HOSTS` 与访问地址不符（改后 `restart vuln-api`） |
| `DisallowedHost` / 本机 curl 得到 400 | 访问用的 Host 不在 `DJANGO_ALLOWED_HOSTS`（对照 §4：已含 127.0.0.1,localhost；改后 `restart vuln-api`） |
| 证据图 403/404 | media 目录权限或不存在：`sudo -u vuln mkdir -p backend/media` + 重新 `chmod -R o+rX backend/media` |
| SSH 被锁 | ufw 先 `allow OpenSSH` 再 enable（§0 顺序勿颠倒） |
