#!/usr/bin/env bash
# Install the private Drive agent beside the public service, under a separate user.

set -Eeuo pipefail
IFS=$'\n\t'

REPOSITORY=/opt/skyseal
AGENT_USER=skyseal-agent
AGENT_GROUP=skyseal-agent
CONFIG_DIR=/etc/skyseal-agent
STATE_DIR=/var/lib/skyseal-agent
PUBLIC_DIR=/var/lib/skyseal-public
GOOGLE_KEY=
GITHUB_TOKEN=
AGENT_TOKEN=/var/lib/skyseal/drive-agent.token.export
DRIVE_FOLDER_ID=

usage() {
  cat <<'EOF'
Usage: sudo bash deploy/bootstrap_agent_vps.sh [options]

Required:
  --google-key FILE       Staged Google service-account JSON (mode 600 or 400)
  --github-token FILE     Staged one-line fine-grained GitHub token (mode 600 or 400)
  --drive-folder-id ID    Dedicated SkySeal Inbox folder ID

Optional:
  --agent-token FILE      Existing one-line Drive-agent token
                          (default: /var/lib/skyseal/drive-agent.token.export)
  --repository DIR        SkySeal checkout (default: /opt/skyseal)
  -h, --help              Show this help

The script copies input secrets into /etc/skyseal-agent with mode 600. It does
not delete the source files. It creates a separate skyseal-agent account,
installs an isolated virtual environment, validates configuration, performs one
scan, and enables the scan and OpenTimestamps-upgrade timers.
EOF
}

log() {
  printf '[skyseal-agent-bootstrap] %s\n' "$*"
}

fail() {
  printf '[skyseal-agent-bootstrap] ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --google-key)
      (($# >= 2)) || fail "--google-key requires a file"
      GOOGLE_KEY=$2
      shift 2
      ;;
    --github-token)
      (($# >= 2)) || fail "--github-token requires a file"
      GITHUB_TOKEN=$2
      shift 2
      ;;
    --agent-token)
      (($# >= 2)) || fail "--agent-token requires a file"
      AGENT_TOKEN=$2
      shift 2
      ;;
    --drive-folder-id)
      (($# >= 2)) || fail "--drive-folder-id requires a value"
      DRIVE_FOLDER_ID=$2
      shift 2
      ;;
    --repository)
      (($# >= 2)) || fail "--repository requires a directory"
      REPOSITORY=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unknown option: $1"
      ;;
  esac
done

((EUID == 0)) || fail "run with sudo"
[[ -n "$GOOGLE_KEY" ]] || fail "--google-key is required"
[[ -n "$GITHUB_TOKEN" ]] || fail "--github-token is required"
[[ "$DRIVE_FOLDER_ID" =~ ^[A-Za-z0-9_-]+$ ]] || fail "invalid Drive folder ID"
[[ -d "$REPOSITORY/.git" ]] || fail "SkySeal repository not found: $REPOSITORY"
[[ -f "$REPOSITORY/drive_agent/agent.py" ]] || fail "Drive agent code is missing"

require_private_file() {
  local path=$1
  local label=$2
  [[ -f "$path" && ! -L "$path" ]] || fail "$label must be a regular, non-symlink file"
  local mode
  mode=$(stat -c '%a' "$path")
  [[ "$mode" =~ ^[0-7]00$ ]] || fail "$label must not be accessible by group or others"
}

require_one_line_secret() {
  local path=$1
  local label=$2
  python3 - "$path" "$label" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
label = sys.argv[2]
try:
    value = path.read_text(encoding="ascii")
except (OSError, UnicodeError) as exc:
    raise SystemExit(f"{label} is not readable ASCII: {type(exc).__name__}")
if not value.endswith("\n") or "\n" in value[:-1] or "\r" in value or not value[:-1]:
    raise SystemExit(f"{label} must contain exactly one non-empty line ending in LF")
PY
}

require_private_file "$GOOGLE_KEY" "Google service-account key"
require_private_file "$GITHUB_TOKEN" "GitHub token"
require_private_file "$AGENT_TOKEN" "SkySeal Drive-agent token"
require_one_line_secret "$GITHUB_TOKEN" "GitHub token"
require_one_line_secret "$AGENT_TOKEN" "SkySeal Drive-agent token"

python3 - "$GOOGLE_KEY" <<'PY'
import json
import pathlib
import sys

try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"Google service-account key is invalid JSON: {type(exc).__name__}")
if value.get("type") != "service_account":
    raise SystemExit("Google credential type is not service_account")
if not str(value.get("client_email", "")).endswith(".gserviceaccount.com"):
    raise SystemExit("Google service-account client_email is invalid")
if not str(value.get("private_key", "")).startswith("-----BEGIN PRIVATE KEY-----"):
    raise SystemExit("Google service-account private key is missing")
PY

python3 - "$AGENT_TOKEN" <<'PY'
import pathlib
import re
import sys

token = pathlib.Path(sys.argv[1]).read_text(encoding="ascii").strip()
if re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
    raise SystemExit("SkySeal Drive-agent token has an invalid format")
PY

log "Installing OS prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates python3 python3-venv util-linux

log "Creating the isolated agent account and private directories"
if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
  adduser --system --group --home /nonexistent --no-create-home "$AGENT_USER"
fi
install -d -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0700 "$CONFIG_DIR" "$STATE_DIR"
install -d -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0700 "$STATE_DIR/work"
install -d -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0755 "$PUBLIC_DIR" "$PUBLIC_DIR/evidence"

log "Installing the isolated Python environment"
if [[ ! -x "$REPOSITORY/.venv-agent/bin/python" ]]; then
  python3 -m venv "$REPOSITORY/.venv-agent"
fi
"$REPOSITORY/.venv-agent/bin/pip" install --disable-pip-version-check \
  -r "$REPOSITORY/verifier/requirements.txt" \
  -r "$REPOSITORY/drive_agent/requirements.txt"

install_secret() {
  local source=$1
  local destination=$2
  if [[ -e "$destination" && ( ! -f "$destination" || -L "$destination" ) ]]; then
    fail "refusing unsafe secret destination: $destination"
  fi
  if [[ -e "$destination" && "$source" -ef "$destination" ]]; then
    chown "$AGENT_USER:$AGENT_GROUP" "$destination"
    chmod 0600 "$destination"
    return
  fi
  if [[ -e "$destination" ]] && ! cmp -s "$source" "$destination"; then
    fail "refusing to replace a different secret: $destination"
  fi
  install -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0600 "$source" "$destination"
}

log "Installing private agent credentials"
install_secret "$GOOGLE_KEY" "$CONFIG_DIR/google-service-account.json"
install_secret "$GITHUB_TOKEN" "$CONFIG_DIR/github.token"
install_secret "$AGENT_TOKEN" "$CONFIG_DIR/drive-agent.token"

ENVIRONMENT_FILE=$(mktemp)
cleanup() {
  rm -f "$ENVIRONMENT_FILE"
}
trap cleanup EXIT
{
  printf 'SKYSEAL_GOOGLE_SERVICE_ACCOUNT=%s\n' "$CONFIG_DIR/google-service-account.json"
  printf 'SKYSEAL_DRIVE_FOLDER_ID=%s\n' "$DRIVE_FOLDER_ID"
  printf 'SKYSEAL_AGENT_SERVER=https://proof.excyberlab.net\n'
  printf 'SKYSEAL_AGENT_RP_ID=proof.excyberlab.net\n'
  printf 'SKYSEAL_AGENT_TOKEN_FILE=%s\n' "$CONFIG_DIR/drive-agent.token"
  printf 'SKYSEAL_GITHUB_OWNER=kagaya\n'
  printf 'SKYSEAL_GITHUB_REPOSITORY=SkySeal\n'
  printf 'SKYSEAL_GITHUB_TOKEN_FILE=%s\n' "$CONFIG_DIR/github.token"
  printf 'SKYSEAL_GITHUB_BRANCH=main\n'
  printf 'SKYSEAL_GITHUB_PREFIX=evidence\n'
  printf 'SKYSEAL_AGENT_DATABASE=%s\n' "$STATE_DIR/drive-agent.sqlite3"
  printf 'SKYSEAL_AGENT_WORK=%s\n' "$STATE_DIR/work"
  printf 'SKYSEAL_PUBLIC_ROOT=%s\n' "$PUBLIC_DIR"
  printf 'SKYSEAL_DRIVE_SETTLE_SECONDS=120\n'
  printf 'SKYSEAL_DRIVE_POLL_SECONDS=30\n'
} >"$ENVIRONMENT_FILE"
install -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0600 \
  "$ENVIRONMENT_FILE" "$CONFIG_DIR/agent.env"

log "Installing and validating systemd units"
install -o root -g root -m 0644 \
  "$REPOSITORY/deploy/skyseal-drive-agent.service" \
  "$REPOSITORY/deploy/skyseal-drive-agent.timer" \
  "$REPOSITORY/deploy/skyseal-ots-upgrade.service" \
  "$REPOSITORY/deploy/skyseal-ots-upgrade.timer" \
  /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify \
  /etc/systemd/system/skyseal-drive-agent.service \
  /etc/systemd/system/skyseal-drive-agent.timer \
  /etc/systemd/system/skyseal-ots-upgrade.service \
  /etc/systemd/system/skyseal-ots-upgrade.timer

log "Performing the first private Drive scan"
systemctl start skyseal-drive-agent.service

log "Enabling recurring Drive scans and timestamp upgrades"
systemctl enable --now skyseal-drive-agent.timer skyseal-ots-upgrade.timer

log "Drive agent setup completed"
systemctl --no-pager --full status skyseal-drive-agent.service || true
systemctl --no-pager list-timers skyseal-drive-agent.timer skyseal-ots-upgrade.timer
printf '\nSource credential files were not deleted. Remove staged copies only after this successful check.\n'
