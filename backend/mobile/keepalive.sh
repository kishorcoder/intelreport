#!/data/data/com.termux/files/usr/bin/bash
# Keeps the Intel API and its Cloudflare tunnel running on the phone: restarts either one
# whenever it exits (crash, network drop, Android killing it), and restarts the API if it
# stops answering health checks. Run it once (or let Termux:Boot run it); stop with stop.sh.
set -u
cd "$(dirname "$0")/.."

LOG_DIR="$HOME"
PORT="$(grep -s '^PORT=' mobile/.env | cut -d= -f2)"
PORT="${PORT:-8200}"
HEALTH_URL="http://127.0.0.1:${PORT}/api/health"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_DIR/intel-keepalive.log"; }

# Hold a wake lock so the CPU and network stay up with the screen off or the phone locked.
command -v termux-wake-lock >/dev/null && termux-wake-lock

supervise() {  # supervise <name> <command...>
  local name=$1; shift
  while true; do
    log "starting $name"
    "$@" >> "$LOG_DIR/intel-$name.log" 2>&1
    log "$name exited with code $?; restarting in 5s"
    sleep 5
  done
}

# Restarts the API when it stops answering (hung, or its network died) — but only after it
# has answered at least once, so the first start (downloading vendor lists) isn't killed.
watchdog() {
  local failures=0 healthy_once=0
  while true; do
    sleep 60
    if curl -fs -m 15 "$HEALTH_URL" > /dev/null; then
      failures=0; healthy_once=1
      continue
    fi
    [ "$healthy_once" = 1 ] || continue
    failures=$((failures + 1))
    log "health check failed ($failures/3)"
    if [ "$failures" -ge 3 ]; then
      log "API not responding; restarting it"
      pkill -f "uvicorn main:app"; sleep 5
      pkill -9 -f "uvicorn main:app"  # a truly hung process ignores the polite signal
      failures=0; healthy_once=0
    fi
  done
}

PIDFILE="$HOME/.intel-keepalive.pid"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "keepalive is already running (logs: ~/intel-*.log). Use ./mobile/stop.sh to stop it."
  exit 0
fi
echo $$ > "$PIDFILE"

log "keepalive started"
supervise backend ./mobile/start.sh &
if grep -qs '^CLOUDFLARE_TUNNEL_TOKEN=.\+' mobile/.env; then
  supervise tunnel ./mobile/tunnel.sh &
else
  log "no CLOUDFLARE_TUNNEL_TOKEN in mobile/.env; tunnel not started"
fi
watchdog &

echo "Intel API and tunnel are running in the background and restart automatically."
echo "Logs: ~/intel-backend.log, ~/intel-tunnel.log, ~/intel-keepalive.log"
echo "Stop everything with: ./mobile/stop.sh"
wait
