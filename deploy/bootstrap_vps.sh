#!/usr/bin/env bash
# Idempotent base setup for the public SkySeal Ubuntu VPS.

set -Eeuo pipefail
IFS=$'\n\t'

TARGET_HOSTNAME="skyseal-proof"
ADMIN_USER="${SUDO_USER:-ubuntu}"
RUN_UPGRADE=1

usage() {
  cat <<'EOF'
Usage: sudo bash deploy/bootstrap_vps.sh [options]

Options:
  --hostname NAME       Hostname to set (default: skyseal-proof)
  --admin-user USER     Existing key-authenticated administrator (default: SUDO_USER or ubuntu)
  --skip-upgrade        Install prerequisites without running apt-get upgrade
  -h, --help            Show this help

The script deliberately does not install an SSH key, reboot the VPS, edit DNS,
or store application secrets. Confirm public-key login before running it.
EOF
}

log() {
  printf '[skyseal-bootstrap] %s\n' "$*"
}

fail() {
  printf '[skyseal-bootstrap] ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --hostname)
      (($# >= 2)) || fail "--hostname requires a value"
      TARGET_HOSTNAME="$2"
      shift 2
      ;;
    --admin-user)
      (($# >= 2)) || fail "--admin-user requires a value"
      ADMIN_USER="$2"
      shift 2
      ;;
    --skip-upgrade)
      RUN_UPGRADE=0
      shift
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

((EUID == 0)) || fail "run with sudo: sudo bash deploy/bootstrap_vps.sh"
[[ "$TARGET_HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || fail "invalid hostname"
[[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "invalid administrator name"

ADMIN_ENTRY="$(getent passwd "$ADMIN_USER" || true)"
[[ -n "$ADMIN_ENTRY" ]] || fail "administrator does not exist: $ADMIN_USER"
ADMIN_HOME="$(cut -d: -f6 <<<"$ADMIN_ENTRY")"
AUTHORIZED_KEYS="$ADMIN_HOME/.ssh/authorized_keys"
[[ -s "$AUTHORIZED_KEYS" ]] || fail "no authorized key found at $AUTHORIZED_KEYS"
ssh-keygen -l -f "$AUTHORIZED_KEYS" >/dev/null 2>&1 || fail "authorized_keys has no readable SSH public key"
ADMIN_GROUP="$(id -gn "$ADMIN_USER")"
chown "$ADMIN_USER:$ADMIN_GROUP" "$ADMIN_HOME/.ssh" "$AUTHORIZED_KEYS"
chmod 0700 "$ADMIN_HOME/.ssh"
chmod 0600 "$AUTHORIZED_KEYS"

log "Refreshing Ubuntu package metadata"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
apt-get update
apt-get install -y ca-certificates curl git python3 python3-venv ufw

log "Setting hostname to $TARGET_HOSTNAME"
hostnamectl set-hostname "$TARGET_HOSTNAME"

log "Creating the restricted SkySeal service account and directories"
if ! id -u skyseal >/dev/null 2>&1; then
  adduser --system --group --home /nonexistent --no-create-home skyseal
fi
install -d -o root -g root -m 0755 /opt/skyseal
install -d -o skyseal -g skyseal -m 0700 /etc/skyseal
install -d -o skyseal -g skyseal -m 0700 /var/lib/skyseal

SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN="$SSHD_DROPIN_DIR/00-skyseal-hardening.conf"
SSHD_NEW="$(mktemp)"
SSHD_BACKUP="$(mktemp)"
SSHD_HAD_PREVIOUS=0

cleanup() {
  rm -f "$SSHD_NEW" "$SSHD_BACKUP"
}
trap cleanup EXIT

cat >"$SSHD_NEW" <<'EOF'
# Managed by SkySeal deploy/bootstrap_vps.sh.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
EOF

install -d -o root -g root -m 0755 "$SSHD_DROPIN_DIR"
if [[ -f "$SSHD_DROPIN" ]]; then
  cp -a "$SSHD_DROPIN" "$SSHD_BACKUP"
  SSHD_HAD_PREVIOUS=1
fi
install -o root -g root -m 0644 "$SSHD_NEW" "$SSHD_DROPIN"

rollback_sshd() {
  if ((SSHD_HAD_PREVIOUS)); then
    cp -a "$SSHD_BACKUP" "$SSHD_DROPIN"
  else
    rm -f "$SSHD_DROPIN"
  fi
}

log "Validating and reloading key-only SSH configuration"
if ! sshd -t; then
  rollback_sshd
  fail "sshd rejected the new configuration; the previous configuration was restored"
fi

SSHD_EFFECTIVE="$(sshd -T)"
for expected in \
  "passwordauthentication no" \
  "kbdinteractiveauthentication no" \
  "permitrootlogin no" \
  "pubkeyauthentication yes"; do
  if ! grep -qx "$expected" <<<"$SSHD_EFFECTIVE"; then
    rollback_sshd
    fail "effective sshd configuration did not contain: $expected"
  fi
done
systemctl reload ssh

log "Allowing only SSH, HTTP, and HTTPS through UFW"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

if ((RUN_UPGRADE)); then
  log "Applying available Ubuntu package upgrades"
  apt-get upgrade -y
fi

log "Base VPS setup completed"
printf '\nEffective SSH policy:\n'
grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication) ' <<<"$SSHD_EFFECTIVE"
printf '\nFirewall status:\n'
ufw status numbered

if [[ -e /var/run/reboot-required ]]; then
  printf '\nA reboot is required to finish package upgrades. Keep this session open,\n'
  printf 'verify a second SSH login first, and then run: sudo reboot\n'
else
  printf '\nKeep this session open until a second public-key SSH login succeeds.\n'
fi
