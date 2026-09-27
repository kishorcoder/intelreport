#!/data/data/com.termux/files/usr/bin/bash
# Exposes the phone's API to the internet through Cloudflare, which works even on mobile
# data where the phone has no public IP.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f mobile/.env ]; then
  set -a
  . mobile/.env
  set +a
fi

if [ -n "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]; then
  exec cloudflared tunnel --no-autoupdate run --token "$CLOUDFLARE_TUNNEL_TOKEN"
else
  echo "No CLOUDFLARE_TUNNEL_TOKEN set: starting a temporary tunnel (URL changes on every restart)."
  exec cloudflared tunnel --no-autoupdate --url "http://localhost:${PORT:-8200}"
fi
