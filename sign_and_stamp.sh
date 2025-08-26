#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# sign_and_stamp.sh  (revised)
# Usage:
#   sign_and_stamp.sh --uid <FPR_or_UID_or_email> [--pubout <publickey.asc>] [--readme <README filename>] [--force] <file>
#
# Example:
#   ./sign_and_stamp.sh --uid "71FC79C05FE638F8BA89CDA6A4AF19F74BA75836" ./document.docx
#
# What it does:
#   1) Creates ASCII-armored detached signature: <file>.asc
#   2) Stamps the signature with OpenTimestamps: <file>.asc.ots (and tries 'ots upgrade')
#   3) Exports the public key: publickey_<uid_sanitized>.asc (or --pubout)
#   4) Generates a bilingual README with verification instructions
#
# Requirements:
#   gpg, ots (optional but recommended)

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "INFO:  $*"; }

GPG_UID=""
PUBOUT=""
README_NAME="README_verification.txt"
FORCE=0

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 --uid <GPG_UID_or_email_or_fingerprint> <file>"
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uid)     shift; GPG_UID="${1:-}"; shift ;;
    --pubout)  shift; PUBOUT="${1:-}";  shift ;;
    --readme)  shift; README_NAME="${1:-}"; shift ;;
    --force|-f) FORCE=1; shift ;;
    -h|--help) grep '^#' "$0"; exit 0 ;;
    -*)        die "Unknown option: $1" ;;
    *)         TARGET_FILE="${1:-}"; shift ;;
  esac
done

[[ -n "${TARGET_FILE:-}" ]] || die "No target file specified."
[[ -n "$GPG_UID"         ]] || die "--uid is required."
[[ -f "$TARGET_FILE"     ]] || die "File not found: $TARGET_FILE"

command -v gpg >/dev/null       || die "gpg not found in PATH"
if command -v ots >/dev/null; then
  OTS_AVAILABLE=1
else
  warn "ots not found, skipping OTS stamping"
  OTS_AVAILABLE=0
fi

# Safer filename generator for Windows/WSL: no colon (:)
sanitize() { LC_ALL=C printf '%s' "$1" | tr -c 'A-Za-z0-9_.@+-' '_' ; }

# Resolve absolute paths
DIR="$(cd "$(dirname "$TARGET_FILE")" && pwd)"
BASE="$(basename "$TARGET_FILE")"
ASC="${BASE}.asc"
OTSFILE="${ASC}.ots"

# Resolve fingerprint early (avoid UID ambiguity)
# Take the first fingerprint that matches the given selector
FPR="$(gpg --fingerprint --with-colons "$GPG_UID" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')"
[[ -n "$FPR" ]] || die "Could not resolve fingerprint for selector '$GPG_UID'"

# Ensure we actually have the secret key for signing
gpg --list-secret-keys "$FPR" >/dev/null 2>&1 || die "Secret key for '$FPR' not found"

if [[ -z "$PUBOUT" ]]; then
  PUBOUT="publickey_$(sanitize "$GPG_UID").asc"
fi

backup_if_exists() {
  local f="$1"
  if [[ -e "$f" && $FORCE -eq 0 ]]; then
    local ts
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    mv -f "$f" "${f}.bak.${ts}"
  fi
}

hash256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "No SHA-256 tool found (need sha256sum or shasum)."
  fi
}

pushd "$DIR" >/dev/null

# 1) GPG sign (armored detached)
backup_if_exists "$ASC"
info "Signing '$BASE' with key $FPR"
gpg --armor --detach-sign --local-user "$FPR" --output "$ASC" -- "$BASE" \
  || die "GPG signing failed. Check your key, pinentry, or passphrase."

# 2) OTS stamp (+ upgrade best-effort)
if [[ $OTS_AVAILABLE -eq 1 ]]; then
  backup_if_exists "$OTSFILE"
  info "Stamping with OpenTimestamps"
  ots stamp "$ASC" || warn "OTS stamp failed (you can retry later)"
  if [[ -f "$OTSFILE" ]]; then
    info "Upgrading OTS proof (best effort)"
    ots upgrade "$OTSFILE" || warn "OTS upgrade failed (can be retried later)"
  fi
fi

# 3) Export public key (by fingerprint)
backup_if_exists "$PUBOUT"
info "Exporting public key to '$PUBOUT'"
gpg --armor --export "$FPR" > "$PUBOUT"

# 4) Hashes & README
H_DOC="$(hash256 "$BASE")"
H_ASC="$(hash256 "$ASC")"

backup_if_exists "$README_NAME"
cat > "$README_NAME" <<EOF
README - 検証手順 / Verification Guide
Generated on: $(date -Iseconds)

対象ファイル / Target file:
- 原本 / Original:           ${BASE}
- 署名 / Signature (.asc):    ${ASC}
- OTS 封緘 / OTS stamp:       ${OTSFILE} $( [[ $OTS_AVAILABLE -eq 1 && -f "$OTSFILE" ]] || echo "(not created)" )
- 公開鍵 / Public key:        ${PUBOUT}

鍵情報 / Key info:
- Selector given: ${GPG_UID}
- Fingerprint:    ${FPR}

ハッシュ / Hashes (SHA-256):
- ${BASE}: ${H_DOC}
- ${ASC}:  ${H_ASC}

==============================
[JA] 検証手順
==============================
1) 公開鍵の指紋確認（以下の FPR と一致すること）:
   ${FPR}
   gpg --show-keys --fingerprint "${PUBOUT}"
2) 公開鍵のインポート:
   gpg --import "${PUBOUT}"
3) GPG 署名の検証:
   gpg --verify "${ASC}" "${BASE}"
4) OTS 検証 (あれば):
   ots verify "${OTSFILE}"

==============================
[EN] Verification Steps
==============================
1) Check the fingerprint matches exactly:
   ${FPR}
   gpg --show-keys --fingerprint "${PUBOUT}"
2) Import public key:
   gpg --import "${PUBOUT}"
3) Verify GPG signature:
   gpg --verify "${ASC}" "${BASE}"
4) Verify OTS proof (if present):
   ots verify "${OTSFILE}"
EOF

popd >/dev/null
info "Done."
