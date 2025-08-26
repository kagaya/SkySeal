#!/usr/bin/env bash
# make_public_hashlist.sh
# 使い方: ./make_public_hashlist.sh <target_folder>
# 指定フォルダ配下の全ファイルの SHA-256 を 1行1ハッシュで
# <YYYYMMDD>_<HHMM>_public.txt に出力します（実行ディレクトリに作成）。

set -euo pipefail
IFS=$'\n\t'

die() { echo "ERROR: $*" >&2; exit 1; }

# 引数チェック
folder="${1:-}"
[ -n "$folder" ] || die "Usage: $0 <target_folder>"
[ -d "$folder" ] || die "Folder not found: $folder"

# 出力ファイル名（ローカルタイム）
timestamp="$(date '+%Y%m%d_%H%M')"
outfile="${timestamp}_public.txt"

# ハッシュコマンドの決定（Linux/macOS対応）
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD=(shasum -a 256)
else
  die "Neither 'sha256sum' nor 'shasum' is available."
fi

# 空ファイルとして作成
: > "$outfile"

# ファイル列挙してハッシュ（NULL区切りで安全）
# ※出力はハッシュのみ
found_any=false
while IFS= read -r -d '' f; do
  found_any=true
  "${HASH_CMD[@]}" "$f" | awk '{print $1}' >> "$outfile"
done < <(find "$folder" -type f -print0)

if ! $found_any; then
  echo "WARN: No files found under '$folder'. Empty list created at '$outfile'." >&2
fi

echo "Wrote hash list: $outfile"
