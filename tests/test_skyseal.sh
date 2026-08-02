#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/skyseal-test.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/input/nested" "$WORK/output"
printf 'alpha\n' >"$WORK/input/a.txt"
printf 'beta\n' >"$WORK/input/nested/b file.txt"

cat >"$WORK/bin/gpg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case " $* " in
  *" --list-secret-keys "*) exit 0 ;;
  *" --fingerprint "*)
    printf 'fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\n'
    ;;
  *" --detach-sign "*)
    output=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "--output" ]]; then output="$2"; shift 2; else shift; fi
    done
    printf '%s\n' 'FAKE SIGNATURE' >"$output"
    ;;
  *" --export "*) printf '%s\n' 'FAKE PUBLIC KEY' ;;
  *) exit 0 ;;
esac
EOF

cat >"$WORK/bin/ots" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "stamp" ]] || exit 2
shift
[[ "${1:-}" == "--" ]] && shift
printf '%s\n' 'FAKE OTS PROOF' >"${1}.ots"
EOF

chmod +x "$WORK/bin/gpg" "$WORK/bin/ots"

(
  cd "$WORK/output"
  PATH="$WORK/bin:$PATH" bash "$ROOT/skyseal" seal --uid test@example.invalid "$WORK/input"
)

hashlist="$(find "$WORK/output" -maxdepth 1 -name '*_public.txt' -type f -print -quit)"
[[ -n "$hashlist" ]]
[[ "$(wc -l <"$hashlist" | tr -d ' ')" == 2 ]]
[[ -f "${hashlist}.asc" ]]
[[ -f "${hashlist}.asc.ots" ]]
[[ -f "$WORK/output/publickey_0123456789ABCDEF0123456789ABCDEF01234567.asc" ]]

if grep -qE 'a\.txt|b file\.txt|input|nested' "$hashlist"; then
  echo 'FAIL: public hash list leaked a source path or filename' >&2
  exit 1
fi

if grep -qEv '^[0-9a-f]{64}$' "$hashlist"; then
  echo 'FAIL: public hash list contains a non-SHA-256 line' >&2
  exit 1
fi

if (
  cd "$WORK/output"
  PATH="$WORK/bin:$PATH" bash "$ROOT/skyseal" seal --uid test@example.invalid "$WORK/input"
) >/dev/null 2>&1; then
  echo 'FAIL: a same-minute output collision was not rejected' >&2
  exit 1
fi

if PATH="/usr/bin:/bin" bash "$ROOT/skyseal" seal --uid test@example.invalid "$WORK/input" >/dev/null 2>&1; then
  echo 'FAIL: sealing unexpectedly succeeded without the OpenTimestamps client' >&2
  exit 1
fi

printf '%s\n' 'PASS: one-command seal workflow'
