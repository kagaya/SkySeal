#!/usr/bin/env bash
# Internal test display only. Keep WebKit's process sandbox enabled.
set -euo pipefail
if [[ -z "${DISPLAY:-}" || "$(id -u)" == 0 ]]; then
  printf '%s\n' 'The Linux GUI smoke test requires an ordinary user in an X11 test display.' >&2
  exit 1
fi
if [[ -n "${WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS:-}" ]]; then
  printf '%s\n' 'Refusing a test environment with the WebKit sandbox disabled.' >&2
  exit 1
fi
openbox >/dev/null 2>&1 &
window_manager_pid=$!
trap 'kill "$window_manager_pid" 2>/dev/null || true' EXIT
export GDK_BACKEND=x11
export LIBGL_ALWAYS_SOFTWARE=1
"$@"
