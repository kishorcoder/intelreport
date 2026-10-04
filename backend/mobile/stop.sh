#!/data/data/com.termux/files/usr/bin/bash
# Stops keepalive.sh, the Intel API and the Cloudflare tunnel, and releases the wake lock.
pkill -f "mobile/keepalive.sh"
rm -f "$HOME/.intel-keepalive.pid"
pkill -f "uvicorn main:app"
pkill -x cloudflared
command -v termux-wake-unlock >/dev/null && termux-wake-unlock
echo "Stopped the Intel API, the tunnel and keepalive."
