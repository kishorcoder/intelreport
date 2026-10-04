#!/data/data/com.termux/files/usr/bin/bash
# Makes Termux:Boot start keepalive.sh (API + tunnel, auto-restarting) when the phone boots.
# Needs the Termux:Boot app installed from F-Droid and opened once.
set -euo pipefail
cd "$(dirname "$0")/.."
BACKEND_DIR="$(pwd)"

mkdir -p "$HOME/.termux/boot"
cat > "$HOME/.termux/boot/intel-backend" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
cd "$BACKEND_DIR"
nohup ./mobile/keepalive.sh > /dev/null 2>&1 &
EOF
chmod +x "$HOME/.termux/boot/intel-backend" mobile/*.sh
echo "Termux:Boot will start ./mobile/keepalive.sh on every boot."
