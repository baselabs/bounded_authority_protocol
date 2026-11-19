#!/usr/bin/env bash
set -euo pipefail

# CI-only runtime checks. Primary versions come from .tool-versions. SDK floors come
# from their manifests: the Rust MSRV from rust-toolchain.toml (also pinned in
# .tool-versions) and the Go floor from the go directive of sdks/go/go.mod.

declared() {
  awk -v tool="$1" '$1 == tool {print $2; found++} END {if (found != 1) exit 1}' .tool-versions
}

# A go directive without a patch level (`go 1.25`) names the .0 release as the floor.
go_floor() {
  floor="$(awk '$1 == "go" {print $2; exit}' sdks/go/go.mod)" || return $?
  case "$floor" in
    '') printf 'sdks/go/go.mod declares no go directive\n' >&2; exit 1 ;;
    *.*.*) ;;
    *) floor="$floor.0" ;;
  esac
  printf '%s\n' "$floor"
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
      case "$tool" in
        golang_floor) value="$(go_floor)" ;;
        *) value="$(declared "$tool")" ;;
      esac
      printf '%s=%s\n' "$tool" "$value" >> "$GITHUB_OUTPUT"
    done
    ;;
  beam)
    expected_elixir="$(declared elixir)"
    expected_otp="$(declared erlang)"
    if [ "$#" = 3 ]; then
      expected_elixir="$2-otp-${3%%.*}"
      expected_otp="$3"
    fi
    actual_elixir="$(elixir -e 'b = System.build_info(); IO.write(b.version <> "-otp-" <> b.otp_release)')"
    actual_otp="$(erl -noshell -eval '
      Path = filename:join([code:root_dir(), "releases", erlang:system_info(otp_release), "OTP_VERSION"]),
      {ok, Version} = file:read_file(Path),
      io:put_chars(string:trim(binary_to_list(Version))), halt().')"
    same Elixir "$expected_elixir" "$actual_elixir"
    same OTP "$expected_otp" "$actual_otp"
    ;;
  python)
    expected="$(declared python)"
    actual="$(python3 -c 'import platform; print(platform.python_version())')"
    same Python "$expected" "$actual"
    ;;
  nodejs)
    expected="$(declared nodejs)"
    actual="$(node -p 'process.versions.node')"
    same Node "$expected" "$actual"
    ;;
  ruby)
    expected="$(declared ruby)"
    actual="$(ruby -e 'print RUBY_VERSION')"
    same Ruby "$expected" "$actual"
    ;;
  golang)
    expected="${2:-}"
    if [ -z "$expected" ]; then
      expected="$(declared golang)"
    fi
    actual="$(GOTOOLCHAIN=local go env GOVERSION | sed 's/^go//')"
    same Go "$expected" "$actual"
    ;;
  golang-floor)
    expected="$(go_floor)"
    actual="$(GOTOOLCHAIN=local go env GOVERSION | sed 's/^go//')"
    same 'Go floor' "$expected" "$actual"
    ;;
  ocaml)
    expected="$(declared ocaml)"
    actual="$(opam exec -- ocamlc -version)"
    same OCaml "$expected" "$actual"
    ;;
  rust)
    expected="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' sdks/rust/rust-toolchain.toml)"
    declared_rust="$(declared rust)"
    actual="$(rustc --version | awk '{print $2}')"
    same 'Rust MSRV' "$declared_rust" "$expected"
    same Rust "$expected" "$actual"
    ;;
  *) printf 'Unknown CI toolchain: %s\n' "$1" >&2; exit 1 ;;
esac
