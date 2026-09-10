# Deploy unit — single-host Ubuntu Docker Compose (Task9)

> 投产前必读：**[GO-LIVE.md](./GO-LIVE.md)** —— 上线准备清单（2 个必须先修的
> 构建缺口、密钥/.env 清单、首个管理员、业务初始化、备份与验收）。
> 本文讲「怎么跑」，GO-LIVE.md 讲「跑之前/之后做什么」。

Wires the LANDED backend (Django/gunicorn + Celery worker + beat + PG16 +
Redis) and the frontend static bundle behind nginx, plus the RSAS FTP drop
path (`ftp` -> `watcher` -> import API).

```
RSAS scanner --FTP:21/PASV--> [ftp: vsftpd, /rsas-drop] --poll--> [watcher]
  --POST /api/imports/rsas?dry_run=false&source=ftp--> [web: nginx]
  --> [api: gunicorn] --> [db: PG16]   (batch visible in ImportMgmt)
[beat] -> cmdb.sync_cmdb (hourly) + check_sla (daily) via [worker] + [redis]
```

## 0. Prerequisites

- Ubuntu 22.04 / 24.04 with the Docker plugin:
  `docker compose version` must work (Compose v2).
- This repo checked out at e.g. `/opt/vuln-ticket` (compose build contexts
  are relative: api/web build from the repo root `..`, ftp/watcher from here).
- Intranet IP of this host at hand (for `PASV_ADDRESS`).
- Out of scope here: Kubernetes/HA, TLS ACME auto-issue, SMS gateway
  (all explicit Phase-2 CUT), and any app code changes.

## 1. Environment setup

```bash
cd deploy
cp .env.example .env && chmod 600 .env
# Edit .env: fill EVERY CHANGE_ME_* value. Secrets have no defaults and
# compose fails fast if they are missing:
#   POSTGRES_PASSWORD / DJANGO_SECRET_KEY / JWT_SECRET_KEY
#   FTP_PASS / WATCHER_TOKEN
# Conditionally required: CMDB_TOKEN (cmdb sync), WECOM_SECRET (WeCom login).
```

Critical knobs:

| Var | Requirement |
|---|---|
| `PASV_ADDRESS` | **Host intranet IP** (e.g. `192.168.1.10`). NEVER `127.0.0.1` — PASV data connections break for every LAN client otherwise. |
| `WATCHER_TOKEN` | JWT of an **operator/service account** (import API is operator-only). |
| `WATCHER_DRY_RUN` | `false` in prod; `true` posts `?dry_run=true` (preview, zero DB writes). |
| `FTP_PORT/PASV_*` | Open `21` + `40000-40100/tcp` in the host firewall (intranet source only). |

## 2. Bring-up (reproducible)

```bash
docker compose up -d --build
docker compose ps
# First boot only: migrate + create the operator the watcher uses:
docker compose exec api python manage.py migrate
docker compose exec api python manage.py createsuperuser
```

Reproducibility check: `docker compose down -v && docker compose up -d --build`
returns to a clean slate (all five named volumes recreated; re-run `migrate`).

## 3. FTP -> watcher -> API e2e test

1. Drop a sample over plaintext FTP (**intranet only** — FTP sends the
   password in cleartext; never expose port 21 to the internet):
   ```bash
   ftp 192.168.1.10  # user $FTP_USER, passive mode on
   put rsas_sample.zip
   ```
2. Watch the handoff:
   ```bash
   docker compose logs -f watcher   # uploaded ... skipped=False counts={...}
   ```
   Re-uploads log `skip-seen` (local seen-state `/state/seen.json`);
   the server `file_hash` check is the second replay defense.
3. Verify in UI: open ImportMgmt — the new batch row appears;
   or `GET /api/imports/batches` (operator token).
4. Dry-run first (optional): set `WATCHER_DRY_RUN=true`, re-up watcher,
   drop a file, confirm `counts` in logs with zero DB writes, then flip back.

## 4. Beat jobs (hourly CMDB pull + daily SLA check)

Beat runs `celery -A config beat`; tasks execute on `worker`. Logs:

```bash
docker compose logs -f beat     # scheduler: next run times
docker compose logs -f worker   # cmdb.sync_cmdb / check_sla results
```

Task names (owned by backend, never redefined here):
`cmdb.sync_cmdb` (hourly) and `apps.tickets.tasks.check_sla` (daily).
The CMDB cursor persists in the `cmdb-cursor` volume
(`CMDB_CURSOR_FILE=/var/lib/cmdb/updated_since`), so hourly runs skip
already-seen rows across restarts.

## 5. Rollback

```bash
docker compose down          # stop, keep data (db-data, rsas-drop, ...)
docker compose down -v       # stop AND wipe all named volumes (fresh start)
```

- Config-only change (nginx/vsftpd/watcher): edit, then
  `docker compose up -d --build <svc>`.
- Bad image: `docker compose pull` n/a (local builds) — `git stash` the
  deploy change and `up -d --build` again; data volumes are untouched
  unless `-v` is passed.

## 6. Manual TLS mount (ACME auto explicitly OUT)

1. Place `fullchain.pem` + `privkey.pem` in `deploy/certs/`
   (directory is git-ignored — never commit keys).
2. Uncomment the cert volumes + 443 port in `docker-compose.yml` (web).
3. Uncomment the 443 server block in `nginx.conf`.
4. `docker compose up -d web`.

## 7. Images & licenses

| Service | Image | License note |
|---|---|---|
| db | `postgres:16-bookworm` | PostgreSQL Licence (permissive) |
| redis | `redis:7-alpine` | RSALv2/SSPL — infra use only, no redistribution |
| api/worker/beat | built `Dockerfile.api` (`python:3.12-slim`) | PSF-licensed base; one build, three commands |
| web | built `Dockerfile.web` (node:20 build + `nginx:1.27-alpine`) | **Chosen approach: web stage builds `../frontend` in-image** (`npm ci && npm run build`); `dist/` is never committed |
| ftp | built `Dockerfile.ftp` (`debian:12-slim` + stock vsftpd) | **vsftpd is GPLv2** — used unmodified as a system component; Debian base is DFSG-free |
| watcher | built `Dockerfile.watcher` (`python:3.12-slim` + `requests==2.32.3`) | Apache-2 dep |

## 8. Backend-env gaps found (reports, NOT patches — lanes own app code)

1. **No `gunicorn` in `backend/requirements.txt`** — `Dockerfile.api`
   pip-installs pinned `gunicorn==23.0.0`. No requirements edit made.
2. **No `CELERY_BEAT_SCHEDULE` anywhere in backend**
   (`backend/config/celery.py` only autodiscovers tasks). The `beat`
   service runs idle-ready and picks schedules up once added; recommended
   addition for the backend lane (hourly CMDB + daily SLA, Asia/Shanghai):
   ```python
   CELERY_BEAT_SCHEDULE = {
     "cmdb-hourly": {"task": "cmdb.sync_cmdb",
                     "schedule": 3600.0},
     "sla-daily": {"task": "apps.tickets.tasks.check_sla",
                   "schedule": {"every": "1 day"},  # or crontab(hour=2, minute=0)
   }}
   ```
3. **No `STATIC_ROOT`/collectstatic wiring in `backend/config/settings.py`**
   (only `STATIC_URL`). nginx proxies `/static/` to api, which 404s under
   `DEBUG=false` until the backend adds `STATIC_ROOT` + collectstatic
   (or WhiteNoise). Frontend SPA itself is unaffected (served from web).
4. `WECOM_AGENTID` is not read by `backend/apps/accounts/wecom.py`
   (only `WECOM_CORPID`/`WECOM_SECRET`), so no such var is documented here.
5. Backend import cap is 50MB (`MAX_UPLOAD_BYTES`); nginx allows 100m so
   the API — not the proxy — is the authority on size rejects.

## 9. K8s/HA — explicitly future work

Single-host compose is the MVP target. Multi-host, PG/Redis HA, shared
storage for `rsas-drop`, and secret management (Vault/SOPS) are Phase-2.
