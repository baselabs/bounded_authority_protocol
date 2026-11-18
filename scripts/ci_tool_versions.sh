#!/bin/bash
# CI-only runtime checks. Primary versions come from .tool-versions; compatibility
# floors are explicit workflow arguments, with Rust also bound to its SDK manifest.
set -euo pipefail

declared() {
  awk -v tool="$1" '$1 == tool {print $2; found++} END {if (found != 1) exit 1}' .tool-versions
}

same() {
  if [ "$2" != "$3" ]; then
    printf '%s version mismatch: declared %s, installed %s\n' "$1" "$2" "$3" >&2
    exit 1
  fi
}

case "$1" in
  read)
    shift
    for tool in "$@"; do
      printf '%s=%s\n' "$tool" "$(declared "$tool")" >> "$GITHUB_OUTPUT"
    done
    ;;
  beam)
    expected_elixir="$(declared elixir)"
    expected_otp="$(declared erlang)"
    if [ "$#" = 3 ]; then
      expected_elixir="$2-otp-${3%%.*}"
      expected_otp="$3"
    fi
    same Elixir "$expected_elixir" "$(elixir -e 'b = System.build_info(); IO.write(b.version <> "-otp-" <> b.otp_release)')"
    same OTP "$expected_otp" "$(erl -noshell -eval '
      Path = filename:join([code:root_dir(), "releases", erlang:system_info(otp_release), "OTP_VERSION"]),
      {ok, Version} = file:read_file(Path),
      io:put_chars(string:trim(binary_to_list(Version))), halt().')"
    ;;
  python) same Python "$(declared python)" "$(python3 -c 'import platform; print(platform.python_version())')" ;;
  nodejs) same Node "$(declared nodejs)" "$(node -p 'process.versions.node')" ;;
  ruby) same Ruby "$(declared ruby)" "$(ruby -e 'print RUBY_VERSION')" ;;
  golang) same Go "${2:-$(declared golang)}" "$(GOTOOLCHAIN=local go env GOVERSION | sed 's/^go//')" ;;
  ocaml) same OCaml "$(declared ocaml)" "$(opam exec -- ocamlc -version)" ;;
  rust)
    expected="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' sdks/rust/rust-toolchain.toml)"
    same 'Rust MSRV' "$(declared rust)" "$expected"
    same Rust "$expected" "$(rustc --version | awk '{print $2}')"
    ;;
  *) printf 'Unknown CI toolchain: %s\n' "$1" >&2; exit 1 ;;
esac
