#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo "~$TARGET_USER")"
MODE="install"
TARGET_UID=""

usage() {
  cat <<'EOF'
Usage:
  sudo ./install.sh [--reinstall|--status]

Options:
  --reinstall   Recreate virtualenv and reinstall python dependencies
  --status      Show diagnostic status only (no changes)
EOF
}

show_recent_logs() {
  local unit="$1"
  local user_mode="${2:-system}"
  if [[ "$user_mode" == "user" ]]; then
    local runtime_dir="/run/user/$TARGET_UID"
    local bus="unix:path=$runtime_dir/bus"
    if [[ -d "$runtime_dir" ]]; then
      runuser -u "$TARGET_USER" -- env XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus" journalctl --user -u "$unit" -n 40 --no-pager || true
    else
      echo "journalctl user logs unavailable: /run/user/$TARGET_UID missing"
    fi
  else
    journalctl -u "$unit" -n 40 --no-pager || true
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reinstall)
      MODE="reinstall"
      shift
      ;;
    --status)
      MODE="status"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root: sudo ./net-monitor/install.sh"
  exit 1
fi

if ! id "$TARGET_USER" >/dev/null 2>&1; then
  echo "Invalid target user: $TARGET_USER"
  exit 1
fi

TARGET_UID="$(id -u "$TARGET_USER")"

check_gi_import() {
  PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" - <<'PY'
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import Gtk  # noqa: F401
from gi.repository import AyatanaAppIndicator3  # noqa: F401
print("GI_IMPORT_OK")
PY
}

check_tray_smoke() {
  PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" - <<'PY'
from net_monitor import tray
print("TRAY_IMPORT_OK", tray.__name__)
PY
}

run_user_systemctl() {
  local action="$1"
  local unit="${2:-}"
  local runtime_dir="/run/user/$TARGET_UID"
  local bus="unix:path=$runtime_dir/bus"
  if [[ -d "$runtime_dir" ]]; then
    if [[ -n "$unit" ]]; then
      runuser -u "$TARGET_USER" -- env XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus" systemctl --user "$action" "$unit"
    else
      runuser -u "$TARGET_USER" -- env XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus" systemctl --user "$action"
    fi
  else
    return 1
  fi
}

if [[ "$MODE" == "status" ]]; then
  echo "[status] target user: $TARGET_USER"
  echo "[status] project dir: $PROJECT_DIR"
  echo "[status] python venv: $PROJECT_DIR/.venv"
  echo "[status] data dir: $USER_HOME/.net-monitor"
  echo
  echo "[status] daemon service"
  systemctl --no-pager --full status net-monitor.service || true
  echo
  echo "[status] tray service"
  if [[ -d "/run/user/$TARGET_UID" ]]; then
    runuser -u "$TARGET_USER" -- env XDG_RUNTIME_DIR="/run/user/$TARGET_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TARGET_UID/bus" systemctl --user --no-pager --full status net-monitor-tray.service || true
  else
    echo "tray status unavailable: no active GUI/user bus"
  fi
  echo
  echo "[status] health files"
  ls -la "$USER_HOME/.net-monitor" 2>/dev/null || true

  echo
  echo "[status] python/gi smoke checks"
  if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    check_gi_import || true
    check_tray_smoke || true
    PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" -m net_monitor --help >/dev/null && echo "CLI_HELP_OK" || true
  else
    echo "VENV_MISSING: run sudo ./install.sh --reinstall"
  fi

  echo
  echo "[status] recent daemon errors (journalctl)"
  show_recent_logs net-monitor.service system

  echo
  echo "[status] recent tray errors (journalctl user)"
  show_recent_logs net-monitor-tray.service user

  echo
  echo "[status] quick diagnosis"
  if systemctl is-active --quiet net-monitor.service; then
    echo "- daemon: active"
  else
    echo "- daemon: NOT active (see daemon journal above)"
  fi
  if [[ -d "/run/user/$TARGET_UID" ]]; then
    if runuser -u "$TARGET_USER" -- env XDG_RUNTIME_DIR="/run/user/$TARGET_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TARGET_UID/bus" systemctl --user is-active --quiet net-monitor-tray.service; then
      echo "- tray: active"
    else
      echo "- tray: NOT active (see tray journal above)"
    fi
  else
    echo "- tray: user bus unavailable (login to desktop and start user service)"
  fi

  echo
  echo "[status] autofix hints"
  echo "- Reinstall dependencies: sudo ./install.sh --reinstall"
  echo "- If tray service cannot connect to bus, login into desktop session and run:"
  echo "  systemctl --user daemon-reload"
  echo "  systemctl --user enable --now net-monitor-tray.service"
  echo "- Verify tray service after login: systemctl --user status net-monitor-tray.service"
  exit 0
fi

echo "[1/8] Install OS dependencies"
apt update
apt install -y \
  python3 python3-pip python3-venv python3-gi \
  gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 \
  libnotify-bin gnome-shell-extension-appindicator

echo "[2/8] Install Python dependencies"
if [[ "$MODE" == "reinstall" && -d "$PROJECT_DIR/.venv" ]]; then
  rm -rf "$PROJECT_DIR/.venv"
fi
if [[ ! -d "$PROJECT_DIR/.venv" ]]; then
  python3 -m venv --system-site-packages "$PROJECT_DIR/.venv"
fi
"$PROJECT_DIR/.venv/bin/python" -m pip install --upgrade pip
"$PROJECT_DIR/.venv/bin/python" -m pip install -r "$PROJECT_DIR/requirements.txt"

echo "[3/8] Prepare data home"
install -d -m 0755 "$USER_HOME/.net-monitor"
chown -R "$TARGET_USER:$TARGET_USER" "$USER_HOME/.net-monitor"

echo "[4/8] Render system service"
sed \
  -e "s|__PROJECT_DIR__|$PROJECT_DIR|g" \
  -e "s|__USER_HOME__|$USER_HOME|g" \
  "$PROJECT_DIR/systemd/net-monitor.service" > /etc/systemd/system/net-monitor.service

sed -i "s|__PYTHON_BIN__|$PROJECT_DIR/.venv/bin/python|g" /etc/systemd/system/net-monitor.service

echo "[5/8] Render user tray service"
install -d -m 0755 "$USER_HOME/.config/systemd/user"
sed \
  -e "s|__PROJECT_DIR__|$PROJECT_DIR|g" \
  "$PROJECT_DIR/systemd/net-monitor-tray.service" > "$USER_HOME/.config/systemd/user/net-monitor-tray.service"

sed -i "s|__PYTHON_BIN__|$PROJECT_DIR/.venv/bin/python|g" "$USER_HOME/.config/systemd/user/net-monitor-tray.service"
chown "$TARGET_USER:$TARGET_USER" "$USER_HOME/.config/systemd/user/net-monitor-tray.service"

echo "[6/8] Enable daemon service"
systemctl daemon-reload
systemctl reset-failed net-monitor.service || true
systemctl enable --now net-monitor.service
if ! systemctl is-active --quiet net-monitor.service; then
  echo "ERROR: net-monitor.service did not start successfully."
  show_recent_logs net-monitor.service system
  exit 1
fi

echo "[7/8] Enable tray service for user"
loginctl enable-linger "$TARGET_USER" || true
if run_user_systemctl daemon-reload; then
  run_user_systemctl enable --now net-monitor-tray.service || true
else
  echo "WARN: user DBus session not available for $TARGET_USER right now."
  echo "After logging into desktop session, run:"
  echo "  systemctl --user daemon-reload"
  echo "  systemctl --user enable --now net-monitor-tray.service"
fi

echo "[7.1/8] Smoke checks"
check_gi_import
check_tray_smoke
PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/python" -m net_monitor --help >/dev/null

echo "[8/8] Status"
systemctl --no-pager --full status net-monitor.service || true
if [[ -d "/run/user/$TARGET_UID" ]]; then
  runuser -u "$TARGET_USER" -- env XDG_RUNTIME_DIR="/run/user/$TARGET_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$TARGET_UID/bus" systemctl --user --no-pager --full status net-monitor-tray.service || true
else
  echo "Tray status unavailable: /run/user/$TARGET_UID is missing (no active GUI session)."
fi

echo

echo "Installation complete"
echo "Runtime data: $USER_HOME/.net-monitor"
echo "Terminal monitor mode: PYTHONPATH=$PROJECT_DIR python3 -m net_monitor monitor"
echo "Full service mode: systemctl status net-monitor.service && systemctl --user status net-monitor-tray.service"
