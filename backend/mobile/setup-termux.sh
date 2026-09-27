#!/data/data/com.termux/files/usr/bin/bash
# One-time setup of the Intel backend on an Android phone running Termux.
set -euo pipefail
cd "$(dirname "$0")/.."
BACKEND_DIR="$(pwd)"

pkg update -y
pkg install -y python python-pip python-cryptography python-greenlet rust binutils cloudflared

# pydantic-core has no Termux package, so pip compiles it with Rust; maturin refuses to
# build for Android without knowing the API level.
export ANDROID_API_LEVEL="$(getprop ro.build.version.sdk)"

python -m venv --system-site-packages .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-mobile.txt

[ -f mobile/.env ] || cp mobile/.env.example mobile/.env
chmod +x mobile/*.sh

# Auto-start on phone boot (needs the Termux:Boot app, opened once).
mkdir -p "$HOME/.termux/boot"
cat > "$HOME/.termux/boot/intel-backend" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
cd "$BACKEND_DIR"
nohup ./mobile/start.sh >> "\$HOME/intel-backend.log" 2>&1 &
if grep -q '^CLOUDFLARE_TUNNEL_TOKEN=.\+' mobile/.env; then
  nohup ./mobile/tunnel.sh >> "\$HOME/intel-tunnel.log" 2>&1 &
fi
EOF
chmod +x "$HOME/.termux/boot/intel-backend"

echo
echo "Setup done. Edit $BACKEND_DIR/mobile/.env, then run: ./mobile/start.sh"
