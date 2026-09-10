# 裸机部署（不用 Docker）

> 可以，全部组件都是标准件：PG16 + Redis + gunicorn + Celery + nginx。
> Docker 版（compose）把它们打包成 6 个容器；本文给**同机裸跑**的等价方案。
> 密钥清单、企微/SMTP/CMDB 准备、业务初始化、备份与验收清单与
> [GO-LIVE.md](./GO-LIVE.md) **完全通用**，本文只讲组件怎么落地（§末附命令对照表）。

## 0. 两条路线，先做选择

| 路线 | 组件 | 适合 |
|---|---|---|
| **最小可用（推荐先走）** | nginx + PG16 + Redis + gunicorn + celery worker/beat，**RSAS 报告走导入页手工上传 ZIP** | 扫描频率不高、有人值班点一下 |
| **完整自动化** | 上述全部 + vsftpd + watch.py（systemd 常驻），FTP 投递→自动入库 | 要全自动管线 |

FTP/watcher 的功能（dry-run 预览、file_hash 去重、来源标记）在手工上传里都有，
**先跑最小路线，自动化以后随时可加**。

## 1. 组件映射（compose → 裸机）

| compose 服务 | 裸机等价 |
|---|---|
| `db` postgres:16 | apt `postgresql-16`（Ubuntu 24.04 自带 16；22.04 加 PGDG 源） |
| `redis` | apt `redis-server`（配置 `appendonly yes` 与 compose 一致） |
| `api` gunicorn | venv + `vuln-api.service`（监听 127.0.0.1:8000，仅本机） |
| `worker` / `beat` | `vuln-worker.service` / `vuln-beat.service` |
| `web` nginx | nginx 站点：前端 dist 静态 + `/api` 反代 |
| `ftp` + `watcher` | 可选：vsftpd + `vuln-watcher.service` |

代码零改动：`settings.py` 的默认值就是同机部署——
`POSTGRES_HOST=localhost`、`REDIS_URL=redis://localhost:6379/0`、
`CELERY_BROKER_URL=redis://localhost:6379/1`、`DB_ENGINE` 默认 postgres。

## 2. 系统依赖（Ubuntu 22.04/24.04）

```bash
sudo apt update
# PostgreSQL 16：24.04 直接装；22.04 先加 PGDG 源
sudo apt install -y postgresql-16 redis-server nginx
# 22.04 才需要：
# sudo install -d /usr/share/postgresql-common/pgdg && \
#   curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | \
#   sudo gpg --dearmor -o /usr/share/postgresql-common/pgdg/apt.gpg && \
#   echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.gpg] https://apt.postgresql.org/pub/repos/apt jammy-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list && sudo apt update
#   sudo apt install -y postgresql-16

# Node 20（前端构建用；两代 Ubuntu 都建议 nodesource）
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs
sudo apt install -y python3.12 python3.12-venv    # 22.04 需要 deadsnakes 或 PGDG 附带
```

## 3. 数据库与目录

```bash
sudo -u postgres psql -c "CREATE USER vuln WITH PASSWORD '换成强密码';"
sudo -u postgres psql -c "CREATE DATABASE vulntickets OWNER vuln;"

sudo useradd -r -m -d /opt/vuln-ticket -s /usr/sbin/nologin vuln || true
sudo install -d -o vuln -g vuln /var/lib/vuln-watcher
sudo mkdir -p /var/www/vuln
```

## 4. 应用代码与环境

```bash
sudo -u vuln git clone <repo> /opt/vuln-ticket   # 或 rsync 已有目录
cd /opt/vuln-ticket
sudo -u vuln python3.12 -m venv .venv
sudo -u vuln .venv/bin/pip install -r backend/requirements.txt gunicorn==23.0.0

# 环境变量：与 GO-LIVE.md §2 同一份 .env，systemd 直接读（KEY=value 格式兼容）
sudo -u vuln cp deploy/.env.example /opt/vuln-ticket/.env && chmod 600 /opt/vuln-ticket/.env
# 编辑 .env：POSTGRES_PASSWORD 与 §3 一致；其余必填项见 GO-LIVE.md §2 表格
# （POSTGRES_HOST/REDIS_URL/CELERY_* 留默认值即同机直连，不用填）
```

## 5. systemd 单元（三个必配）

```ini
# /etc/systemd/system/vuln-api.service
[Unit]
Description=vuln-ticket API (gunicorn)
After=network.target postgresql.service redis-server.service

[Service]
User=vuln
Group=vuln
WorkingDirectory=/opt/vuln-ticket/backend
EnvironmentFile=/opt/vuln-ticket/.env
ExecStart=/opt/vuln-ticket/.venv/bin/gunicorn config.wsgi:application \
    --bind 127.0.0.1:8000 --workers 3 --timeout 300 --access-logfile -
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/vuln-worker.service
[Unit]
Description=vuln-ticket Celery worker
After=network.target redis-server.service postgresql.service

[Service]
User=vuln
Group=vuln
WorkingDirectory=/opt/vuln-ticket/backend
EnvironmentFile=/opt/vuln-ticket/.env
ExecStart=/opt/vuln-ticket/.venv/bin/celery -A config worker --loglevel=INFO --concurrency=2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/vuln-beat.service
[Unit]
Description=vuln-ticket Celery beat
After=vuln-worker.service

[Service]
User=vuln
Group=vuln
WorkingDirectory=/opt/vuln-ticket/backend
EnvironmentFile=/opt/vuln-ticket/.env
ExecStart=/opt/vuln-ticket/.venv/bin/celery -A config beat --loglevel=INFO
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vuln-api vuln-worker vuln-beat
```

迁移与首个管理员（等价于 GO-LIVE.md §5，注意 `createsuperuser` 建出来是
owner 不是系统管理员，必须指定 role=admin）：
```bash
cd /opt/vuln-ticket/backend
sudo -u vuln ../.venv/bin/python manage.py migrate
sudo -u vuln ../.venv/bin/python manage.py collectstatic --noinput
sudo -u vuln ../.venv/bin/python manage.py shell -c "
from apps.accounts.models import User
u = User(username='admin', role='admin', is_active=True, dept='安全运营')
u.set_password('改成强密码'); u.save(); print('admin created')"
```

## 6. 前端构建 + nginx 站点

```bash
cd /opt/vuln-ticket/frontend
sudo -u vuln npm ci
sudo -u vuln env VITE_API_BASE= VITE_WECOM_CORPID= VITE_WECOM_AGENTID= npm run build
# 同 GO-LIVE §0：VITE_* 是构建期烘焙；API_BASE 留空=同源，企微参数有了再填并重建
sudo rsync -a --delete dist/ /var/www/vuln/
```

nginx 站点 `/etc/nginx/sites-available/vuln`（基于 deploy/nginx.conf 改路径）：
```nginx
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
    location /media/  { alias /opt/vuln-ticket/backend/media/; }   # 工单证据图
    location / { root /var/www/vuln; index index.html; try_files $uri $uri/ /index.html; }
}
```
```bash
sudo ln -sf /etc/nginx/sites-available/vuln /etc/nginx/sites-enabled/vuln
sudo rm -f /etc/nginx/sites-enabled/default
# nginx(www-data) 要能读到 media/staticfiles：
sudo chmod -R o+rX /opt/vuln-ticket/backend/media /opt/vuln-ticket/backend/staticfiles
sudo nginx -t && sudo systemctl reload nginx
```
> 证据图上传后新增文件同样要 www-data 可读：给 `backend/media` 加个
> `o+rX` 的 tmpfiles.d 规则，或上传目录固定组权限（部署后一次性处理）。

## 7. 可选：FTP 自动化路线

- **vsftpd**：参考 `deploy/vsftpd.conf`（同样 `pasv_address=本机内网 IP`，
  防火墙 21 + 40000-40100 只放行扫描器来源 IP），本地投递目录如 `/srv/rsas-drop`。
- **watcher**：`deploy/watcher/watch.py` 是独立脚本，systemd 常驻：
  ```ini
  # /etc/systemd/system/vuln-watcher.service
  [Service]
  User=vuln
  EnvironmentFile=/opt/vuln-ticket/.env
  Environment=API_BASE=http://127.0.0.1:8000
  Environment=WATCH_DIR=/srv/rsas-drop
  Environment=STATE_FILE=/var/lib/vuln-watcher/seen.json
  Environment=WATCHER_TOKEN=同GO-LIVE签发
  Environment=DRY_RUN=true
  ExecStart=/opt/vuln-ticket/.venv/bin/python /opt/vuln-ticket/deploy/watcher/watch.py
  Restart=always
  ```
  注意：watch.py 读的环境名是 `DRY_RUN`（compose 里才做 `WATCHER_DRY_RUN`→
  `DRY_RUN` 的映射）；`WATCHER_TOKEN` 60 分钟过期问题同 GO-LIVE §2。
- 或干脆不加：`/imports` 页面手工传 ZIP（支持 dry-run 预览与来源标记）。

## 8. 与 Docker 版的命令对照

| Docker | 裸机 |
|---|---|
| `docker compose exec api python manage.py migrate` | `sudo -u vuln .venv/bin/python manage.py migrate`（backend/ 下） |
| `docker compose logs -f api` | `journalctl -u vuln-api -f`（worker/beat 同理） |
| `docker compose up -d --build` | `git pull` + 重建 venv（如有依赖变更）+ 前端 `npm run build` + `systemctl restart vuln-api vuln-worker vuln-beat` + reload nginx |
| 备份 `docker compose exec db pg_dump ...` | `sudo -u postgres pg_dump vulntickets \| gzip > ...` |
| 卷备份 media-data | 备份 `/opt/vuln-ticket/backend/media/` |

## 9. 取舍提醒

- systemd `Restart=always` 等价 compose 的 `restart: always`；但没有 healthcheck
  自愈，建议加个 cron 探活 `curl -fs http://127.0.0.1:8000/api/auth/me`。
- 进程同机共享环境，升级回滚靠 git + `pip freeze` 快照（升级前记一份）。
- 证据图/数据库/静态卷都在本机磁盘——备份策略（GO-LIVE §8）不变，路径换成上表。
- GO-LIVE.md 的验收清单（§9）**逐项适用**，把 docker 命令按 §8 对照替换。
