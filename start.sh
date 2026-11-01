#!/usr/bin/env bash
# ISeeCode start script: requires AUTH_TOKEN; browser login needs AUTH_USER/AUTH_PASS.
set -e
cd "$(dirname "$0")"

if [ -z "${AUTH_TOKEN:-}" ]; then
  echo "请先设置 AUTH_TOKEN，例如:" >&2
  echo "  export AUTH_TOKEN=\$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')" >&2
  exit 1
fi
export AUTH_TOKEN
export AUTH_USER="${AUTH_USER:-admin}"
export AUTH_PASS="${AUTH_PASS:-}"
export TZ="${TZ:-Asia/Shanghai}"
# 开源规则包：test = gosec/njsscan 移植；off 关闭；extended 预留
export AUDIT_RULE_PACKS_MODE="${AUDIT_RULE_PACKS_MODE:-test}"
export AUDIT_MOBSF_URL="${AUDIT_MOBSF_URL:-http://127.0.0.1:8010}"
export AUDIT_MOBSF_KEY="${AUDIT_MOBSF_KEY:-}"

if [ ! -f .venv/bin/activate ]; then
  echo "缺少 .venv，请先执行:" >&2
  echo "  python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi
source .venv/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" > uvicorn.log 2>&1 < /dev/null &
echo "PID=$!"
