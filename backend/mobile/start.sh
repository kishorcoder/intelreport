#!/data/data/com.termux/files/usr/bin/bash
# Runs the Intel API on the phone, reachable from other devices.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f mobile/.env ]; then
  set -a
  . mobile/.env
  set +a
fi
[ -n "${CORS_ALLOWED_ORIGINS:-}" ] || unset CORS_ALLOWED_ORIGINS

# Stop Android from suspending the process when the screen turns off.
command -v termux-wake-lock >/dev/null && termux-wake-lock

. .venv/bin/activate

# One worker: each worker would load its own copy of the blocklists into the phone's RAM.
# Proxy headers from the local tunnel are trusted so rate limiting sees real client IPs
# instead of every tunnelled request sharing 127.0.0.1's limit.
exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8200}" \
  --workers 1 \
  --proxy-headers \
  --forwarded-allow-ips 127.0.0.1
