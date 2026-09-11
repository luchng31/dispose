#!/usr/bin/env bash
# 开发机 → 裸机服务器 一键推送更新（不依赖 git 仓库）
#
# 用法（开发机上）:
#   bash deploy/push.sh <服务器IP>        # 例: bash deploy/push.sh 192.168.91.130
#
# 前置（只在第一次）:
#   ssh-copy-id ubuntu@<服务器IP>         # 免密 ssh，之后 rsync/ssh 不再要密码
#
# 保护约定（不会被覆盖/删除的服务器侧文件）:
#   /opt/vuln-ticket/.env                 服务器密钥配置
#   backend/media/                        工单证据图
#   backend/staticfiles/                  服务端生成的静态文件
#   .git/                                 若做过 git 接入
set -euo pipefail

HOST="${1:?用法: bash deploy/push.sh <服务器IP>}"
STAGE="/home/ubuntu/vuln-stage"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 与 .gitignore 对齐的排除清单（运行时数据/本地产物永不进服务器）
EXCLUDES=(
  --exclude .git --exclude .env --exclude db.sqlite3
  --exclude backend/media --exclude backend/staticfiles
  --exclude node_modules --exclude __pycache__ --exclude '*.pyc'
  --exclude .venv --exclude .omo --exclude .opencode --exclude .codegraph
  --exclude .pytest_cache --exclude .ruff_cache
  --exclude '*.xlsx' --exclude '*扫描*' --exclude '*.log'
  --exclude deploy/certs
)

echo "==> 1/4 构建前端（VITE_API_BASE 留空=同源 /api；约半分钟）"
(
  cd "$ROOT/frontend"
  VITE_API_BASE= VITE_WECOM_CORPID="${VITE_WECOM_CORPID:-}" \
    VITE_WECOM_AGENTID="${VITE_WECOM_AGENTID:-}" npm run build
)

echo "==> 2/4 rsync 代码 → ${HOST}:${STAGE}"
rsync -a --delete "${EXCLUDES[@]}" "$ROOT/" "ubuntu@${HOST}:${STAGE}/"

echo "==> 3/4 服务器落盘 + 迁移 + 重启（输入 ubuntu 的 sudo 密码）"
# 同一份排除清单必须在接收侧再生效一次：--delete 会删掉接收端多出来的文件，
# 不排除 .venv/node_modules 的话服务器上的运行环境会被整个清掉
REMOTE_EXCLUDES=""
for e in "${EXCLUDES[@]}"; do
  REMOTE_EXCLUDES+=" --exclude $(printf '%q' "$e")"
done
ssh -t "ubuntu@${HOST}" "
set -e
sudo rsync -a --delete ${REMOTE_EXCLUDES} ${STAGE}/ /opt/vuln-ticket/
sudo chown -R vuln:vuln /opt/vuln-ticket
sudo -u vuln /opt/vuln-ticket/.venv/bin/pip install -q -r /opt/vuln-ticket/backend/requirements.txt
sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py migrate --noinput'
sudo -u vuln bash -c 'set -a; . /opt/vuln-ticket/.env; set +a; cd /opt/vuln-ticket/backend && /opt/vuln-ticket/.venv/bin/python manage.py collectstatic --noinput'
sudo rsync -a --delete /opt/vuln-ticket/frontend/dist/ /var/www/vuln/
sudo systemctl restart vuln-api vuln-worker vuln-beat
sudo systemctl reload nginx
"

echo "==> 4/4 烟测"
CODE=$(curl -s "http://${HOST}/api/auth/me" -o /dev/null -w "%{http_code}")
echo "GET /api/auth/me -> ${CODE}（403=正常，未带 token 的拒绝）"
echo "完成。浏览器打开 http://${HOST} 确认页面与数据。"
