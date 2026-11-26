#!/usr/bin/env bash
set -euo pipefail

version=${1:?"usage: scripts/install_sqlite.sh VERSION DESTINATION_DIRECTORY"}
destination=${2:?"usage: scripts/install_sqlite.sh VERSION DESTINATION_DIRECTORY"}

case "$version" in
  3.54.1)
    url='https://sqlite.org/2026/sqlite-tools-linux-x64-3540100.zip'
    sha3='555635de98534d87a67ee2e6e1b0d79f494b1b33b223477d3e7a8ea0c66e416f'
    ;;
  *)
    printf 'SQLite archive is unpinned for version %s\n' "$version" >&2
    exit 1
    ;;
esac

work_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bap-sqlite-install.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
trap 'exit 1' HUP INT TERM

archive="$work_dir/sqlite.zip"
curl -fsSLo "$archive" "$url"
checksum=$(openssl dgst -sha3-256 -r "$archive")
if [ "${checksum%% *}" != "$sha3" ]; then
  printf 'SQLite archive checksum mismatch\n' >&2
  exit 1
fi

unzip -p "$archive" sqlite3 > "$work_dir/sqlite3"
chmod 0755 "$work_dir/sqlite3"
installed=$("$work_dir/sqlite3" --version)
if [ "${installed%% *}" != "$version" ]; then
  printf 'SQLite reports %s, expected %s\n' "${installed%% *}" "$version" >&2
  exit 1
fi

mkdir -p "$destination"
install -m 0755 "$work_dir/sqlite3" "$destination/sqlite3"
printf '%s\n' "$destination" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
