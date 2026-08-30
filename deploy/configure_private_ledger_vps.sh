#!/usr/bin/env bash
# Enable the owner-only Google Sheets ledger on an existing production agent.

set -Eeuo pipefail
IFS=$'\n\t'

ENV_FILE=/etc/skyseal-agent/agent.env
AGENT_USER=skyseal-agent
SPREADSHEET_ID=
SHEET=Ledger
SHEET_RE='^[A-Za-z0-9 _-]{1,50}$'

usage() {
  cat <<'EOF'
Usage: sudo bash deploy/configure_private_ledger_vps.sh --spreadsheet-id ID [--sheet Ledger]

Before running, create a Google Sheet owned by the SkySeal owner, rename its
tab to Ledger, and share that Sheet as Editor only with the existing SkySeal
service-account email. Do not enable link sharing.
EOF
}

fail() {
  printf '[skyseal-private-ledger] ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --spreadsheet-id)
      (($# >= 2)) || fail "--spreadsheet-id requires a value"
      SPREADSHEET_ID=$2
      shift 2
      ;;
    --sheet)
      (($# >= 2)) || fail "--sheet requires a value"
      SHEET=$2
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
[[ "$SPREADSHEET_ID" =~ ^[A-Za-z0-9_-]+$ ]] || fail "invalid spreadsheet ID"
[[ "$SHEET" =~ $SHEET_RE ]] || fail "invalid sheet name"
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || fail "agent environment file is missing"

TEMP=$(mktemp)
cleanup() { rm -f "$TEMP"; }
trap cleanup EXIT

awk -F= '
  $1 != "SKYSEAL_PRIVATE_LEDGER_SPREADSHEET_ID" &&
  $1 != "SKYSEAL_PRIVATE_LEDGER_SHEET" { print }
' "$ENV_FILE" >"$TEMP"
printf 'SKYSEAL_PRIVATE_LEDGER_SPREADSHEET_ID=%s\n' "$SPREADSHEET_ID" >>"$TEMP"
printf 'SKYSEAL_PRIVATE_LEDGER_SHEET=%s\n' "$SHEET" >>"$TEMP"
install -o "$AGENT_USER" -g "$AGENT_USER" -m 0600 "$TEMP" "$ENV_FILE"

printf '[skyseal-private-ledger] Validating the private Sheet and header\n'
sudo -u "$AGENT_USER" env \
  XDG_CACHE_HOME=/var/lib/skyseal-agent/cache \
  PATH=/opt/skyseal/.venv-agent/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin \
  bash -c 'set -a; . /etc/skyseal-agent/agent.env; set +a; exec /opt/skyseal/.venv-agent/bin/python /opt/skyseal/drive_agent/agent.py ledger-check'

printf '[skyseal-private-ledger] Enabled. Future approved seals will sync to the owner-only Sheet.\n'
