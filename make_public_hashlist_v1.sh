#!/usr/bin/env bash
# Create a strict skyseal-sha256-set-v1 commitment without publishing names.
# Usage: ./make_public_hashlist_v1.sh [--output FILE] TARGET_FOLDER

set -euo pipefail
IFS=$'\n\t'

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: ./make_public_hashlist_v1.sh [--output FILE] TARGET_FOLDER

Creates a non-empty, sorted, duplicate-free list of lowercase SHA-256 values.
The output contains no source file names or paths. Existing output files are
never overwritten.
EOF
}

output=""
target=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      shift
      [[ $# -gt 0 ]] || die "--output requires a file path"
      output="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      die "Unknown option: $1"
      ;;
    *)
      [[ -z "$target" ]] || die "Only one target folder may be supplied"
      target="$1"
      shift
      ;;
  esac
done

[[ -n "$target" ]] || die "A target folder is required"
[[ -d "$target" ]] || die "Target folder not found"

if [[ -z "$output" ]]; then
  output="$(date '+%Y%m%d_%H%M')_public.txt"
fi
[[ ! -e "$output" ]] || die "Output already exists; refusing to overwrite"
output_parent="$(dirname -- "$output")"
[[ -d "$output_parent" ]] || die "Output directory not found"

if command -v sha256sum >/dev/null 2>&1; then
  hash_command=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash_command=(shasum -a 256)
else
  die "Neither sha256sum nor shasum is available"
fi

umask 077
work_dir="$(mktemp -d)"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT HUP INT TERM

# File names exist only in this private temporary file and never in the public
# commitment. Creating the final output is deferred so an output inside the
# target cannot hash itself.
find "$target" -type f -print0 > "$work_dir/files"

file_count=0
while IFS= read -r -d '' source_file; do
  digest="$("${hash_command[@]}" < "$source_file" | awk '{print $1}')"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "Hash command returned an invalid digest"
  printf '%s\n' "$digest" >> "$work_dir/hashes"
  file_count=$((file_count + 1))
done < "$work_dir/files"

[[ $file_count -gt 0 ]] || die "Target contains no regular files; empty commitments are forbidden"
LC_ALL=C sort -u "$work_dir/hashes" > "$work_dir/public.txt"

# noclobber makes the final existence check atomic for a local filesystem.
if ! (set -o noclobber; command cat "$work_dir/public.txt" > "$output"); then
  die "Output appeared during processing; refusing to overwrite"
fi
chmod 0644 "$output"

distinct_count="$(wc -l < "$work_dir/public.txt" | tr -d '[:space:]')"
echo "Wrote $distinct_count distinct hashes from $file_count files to $output"
