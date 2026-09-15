#!/bin/sh
set -eu

expected_version='8.30.1'

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "secret scan must run inside a Git repository" >&2
  exit 1
}
config="$repo_root/.gitleaks.toml"

require_version() {
  expected=$1
  if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks $expected is required; install the official release and place it on PATH" >&2
    return 1
  fi
  actual=$(gitleaks version 2>/dev/null) || {
    echo "could not read the gitleaks version; install gitleaks $expected" >&2
    return 1
  }
  if [ "$actual" != "$expected" ]; then
    echo "gitleaks $expected is required; found $actual. Install the official $expected release." >&2
    return 1
  fi
}

run_gitleaks() {
  GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=color.ui \
    GIT_CONFIG_VALUE_0=false \
    GIT_CONFIG_KEY_1=diff.noprefix \
    GIT_CONFIG_VALUE_1=false \
    GIT_CONFIG_KEY_2=diff.mnemonicPrefix \
    GIT_CONFIG_VALUE_2=false \
    gitleaks "$@"
}

run_git_isolated() {
  GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_CONFIG_COUNT=3 \
    GIT_CONFIG_KEY_0=color.ui \
    GIT_CONFIG_VALUE_0=false \
    GIT_CONFIG_KEY_1=diff.noprefix \
    GIT_CONFIG_VALUE_1=false \
    GIT_CONFIG_KEY_2=diff.mnemonicPrefix \
    GIT_CONFIG_VALUE_2=false \
    git "$@"
}

assert_history_safe() {
  scan_root=$1
  if [ "${GIT_GRAFT_FILE+x}" = 'x' ]; then
    echo "secret history scan refuses GIT_GRAFT_FILE" >&2
    return 1
  fi
  if [ "${GIT_SHALLOW_FILE+x}" = 'x' ]; then
    echo "secret history scan refuses GIT_SHALLOW_FILE" >&2
    return 1
  fi
  if [ "${GIT_REPLACE_REF_BASE+x}" = 'x' ]; then
    echo "secret history scan refuses GIT_REPLACE_REF_BASE" >&2
    return 1
  fi
  shallow=$(git --no-replace-objects -C "$scan_root" rev-parse --is-shallow-repository)
  if [ "$shallow" != 'false' ]; then
    echo "secret history scan requires a complete, non-shallow repository" >&2
    return 1
  fi
  if [ -n "$(git --no-replace-objects -C "$scan_root" for-each-ref --format='%(refname)' refs/replace)" ]; then
    echo "secret history scan refuses Git replace refs" >&2
    return 1
  fi
  grafts=$(git --no-replace-objects -C "$scan_root" rev-parse --git-path info/grafts)
  case "$grafts" in
    /*) ;;
    *) grafts="$scan_root/$grafts" ;;
  esac
  if [ -s "$grafts" ]; then
    echo "secret history scan refuses Git grafts" >&2
    return 1
  fi
}

history_scan() (
  assert_history_safe "$repo_root"
  if ! run_git_isolated -C "$repo_root" log -p -U0 \
    --full-history --diff-merges=separate HEAD -- >/dev/null; then
    echo "secret history scan could not read history under the scanner's isolated Git configuration" >&2
    exit 1
  fi
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='--full-history --diff-merges=separate HEAD' "$repo_root"
)

staged_scan() {
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --staged "$repo_root"
}

unstaged_scan() {
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --pre-commit "$repo_root"
}

write_pat() {
  target=$1
  prefix=$(printf 'gh%s_' 'p')
  suffix=$(openssl rand -hex 18)
  printf '%s%s\n' "$prefix" "$suffix" > "$target"
  printf '%s%s' "$prefix" "$suffix"
}

write_generic_key() {
  target=$1
  value=$(openssl rand -hex 24)
  printf '{"key_fingerprint": "%s"}\n' "$value" > "$target"
  printf '%s' "$value"
}

write_jwt() {
  target=$1
  header=$(printf '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  payload=$(printf '{"sub":"runtime-sensitivity-probe","iat":1}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  signature=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
  printf '%s.%s.%s\n' "$header" "$payload" "$signature" > "$target"
  printf '%s.%s.%s' "$header" "$payload" "$signature"
}

assert_redacted_finding() {
  report=$1
  stdout_file=$2
  stderr_file=$3
  canary=$4
  expected_rule=$5
  exit_code=$6
  if [ "$exit_code" -ne 42 ]; then
    echo "expected finding exit 42, got $exit_code" >&2
    return 1
  fi
  grep -F '"RuleID": "'"$expected_rule"'"' "$report" >/dev/null
  if grep -F "$canary" "$stdout_file" "$stderr_file" "$report" >/dev/null; then
    echo "redacted scanner output exposed a canary" >&2
    return 1
  fi
}

assert_rule_paths() {
  report=$1
  expected_rule=$2
  expected_paths=$3
  python3 - "$report" "$expected_rule" "$expected_paths" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    findings = json.load(handle)
with open(sys.argv[3], encoding="utf-8") as handle:
    expected = {line.rstrip("\n") for line in handle if line.rstrip("\n")}
observed = {
    finding.get("File")
    for finding in findings
    if finding.get("RuleID") == sys.argv[2]
}
missing = expected - observed
if missing:
    raise SystemExit(f"{sys.argv[2]} sensitivity missed {len(missing)} path group(s)")
PY
}

run_check() {
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_NOSYSTEM=1
  GIT_CONFIG_COUNT=0
  export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT

  if require_version '0.0.0' > /dev/null 2>&1; then
    echo "wrong-version self-check did not fail" >&2
    return 1
  fi
  require_version "$expected_version"
  "$repo_root/scripts/install_gitleaks.sh" --check

  check_dir=$(mktemp -d "${TMPDIR:-/tmp}/bap-secret-scan.XXXXXX")
  trap 'rm -rf "$check_dir"' EXIT HUP INT TERM

  hostile_git_config="$check_dir/hostile-global.gitconfig"
  git config --file "$hostile_git_config" color.ui always
  git config --file "$hostile_git_config" diff.noprefix true
  git config --file "$hostile_git_config" diff.mnemonicPrefix true
  positive_noprefix=$(GIT_CONFIG_GLOBAL="$hostile_git_config" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_COUNT=0 \
    git config --global --get diff.noprefix)
  if [ "$positive_noprefix" != 'true' ]; then
    echo "hostile Git-config positive control failed" >&2
    return 1
  fi
  if git config --global --get diff.noprefix >/dev/null 2>&1; then
    echo "secret-scan test Git inherited global configuration" >&2
    return 1
  fi

  guard_repo="$check_dir/history-guard"
  mkdir -p "$guard_repo"
  git -C "$guard_repo" init -q -b main
  git -C "$guard_repo" config user.name 'Secret Scan Probe'
  git -C "$guard_repo" config user.email 'probe@example.invalid'
  ln -s "$config" "$guard_repo/.gitleaks.toml"
  printf 'one\n' > "$guard_repo/guard.txt"
  git -C "$guard_repo" add guard.txt
  git -C "$guard_repo" -c core.hooksPath=/dev/null commit -q -m 'history guard root'
  printf 'two\n' > "$guard_repo/guard.txt"
  git -C "$guard_repo" add guard.txt
  git -C "$guard_repo" -c core.hooksPath=/dev/null commit -q -m 'history guard head'
  (cd "$guard_repo" && "$repo_root/scripts/secret_scan.sh" --history) \
    > "$check_dir/history-guard-green.stdout" 2> "$check_dir/history-guard-green.stderr"

  safe_directory_config="$check_dir/safe-directory.gitconfig"
  git config --file "$safe_directory_config" --add safe.directory "$guard_repo"
  if (cd "$guard_repo" && \
    GIT_TEST_ASSUME_DIFFERENT_OWNER=1 GIT_CONFIG_GLOBAL="$safe_directory_config" \
      "$repo_root/scripts/secret_scan.sh" --history) \
    > "$check_dir/history-guard-safe-directory.stdout" 2> "$check_dir/history-guard-safe-directory.stderr"; then
    echo "safe-directory isolated-history self-check did not fail" >&2
    return 1
  fi
  grep -F "secret history scan could not read history under the scanner's isolated Git configuration" \
    "$check_dir/history-guard-safe-directory.stderr" >/dev/null

  shallow_path=$(git --no-replace-objects -C "$guard_repo" rev-parse --git-path shallow)
  case "$shallow_path" in
    /*) ;;
    *) shallow_path="$guard_repo/$shallow_path" ;;
  esac
  printf '%s\n' "$(git --no-replace-objects -C "$guard_repo" rev-parse HEAD^)" > "$shallow_path"
  if (cd "$guard_repo" && "$repo_root/scripts/secret_scan.sh" --history) \
    > "$check_dir/history-guard-shallow.stdout" 2> "$check_dir/history-guard-shallow.stderr"; then
    echo "shallow-history self-check did not fail" >&2
    return 1
  fi
  grep -F 'requires a complete, non-shallow repository' "$check_dir/history-guard-shallow.stderr" >/dev/null
  rm "$shallow_path"

  guard_head=$(git --no-replace-objects -C "$guard_repo" rev-parse HEAD)
  guard_parent=$(git --no-replace-objects -C "$guard_repo" rev-parse HEAD^)
  git -C "$guard_repo" replace "$guard_head" "$guard_parent"
  if (cd "$guard_repo" && "$repo_root/scripts/secret_scan.sh" --history) \
    > "$check_dir/history-guard-replace.stdout" 2> "$check_dir/history-guard-replace.stderr"; then
    echo "replace-ref self-check did not fail" >&2
    return 1
  fi
  grep -F 'refuses Git replace refs' "$check_dir/history-guard-replace.stderr" >/dev/null
  git -C "$guard_repo" replace -d "$guard_head" >/dev/null

  grafts_path=$(git --no-replace-objects -C "$guard_repo" rev-parse --git-path info/grafts)
  case "$grafts_path" in
    /*) ;;
    *) grafts_path="$guard_repo/$grafts_path" ;;
  esac
  mkdir -p "$(dirname "$grafts_path")"
  printf '%s %s\n' "$guard_head" "$guard_parent" > "$grafts_path"
  if (cd "$guard_repo" && "$repo_root/scripts/secret_scan.sh" --history) \
    > "$check_dir/history-guard-grafts.stdout" 2> "$check_dir/history-guard-grafts.stderr"; then
    echo "grafts self-check did not fail" >&2
    return 1
  fi
  grep -F 'refuses Git grafts' "$check_dir/history-guard-grafts.stderr" >/dev/null
  rm "$grafts_path"

  alternate_grafts="$check_dir/alternate-grafts"
  printf '%s %s\n' "$guard_head" "$guard_parent" > "$alternate_grafts"
  if (cd "$guard_repo" && GIT_GRAFT_FILE="$alternate_grafts" "$repo_root/scripts/secret_scan.sh" --history) \
    > "$check_dir/history-guard-alternate-grafts.stdout" 2> "$check_dir/history-guard-alternate-grafts.stderr"; then
    echo "alternate-grafts self-check did not fail" >&2
    return 1
  fi
  grep -F 'refuses GIT_GRAFT_FILE' "$check_dir/history-guard-alternate-grafts.stderr" >/dev/null

  git -C "$guard_repo" -c core.hooksPath=/dev/null commit -q --allow-empty -m 'empty history edge'
  head -c 128 /dev/urandom > "$guard_repo/binary.bin"
  git -C "$guard_repo" add binary.bin
  git -C "$guard_repo" -c core.hooksPath=/dev/null commit -q -m 'binary history edge'
  git -C "$guard_repo" checkout -q -b history-edge-side
  printf 'side\n' > "$guard_repo/side.txt"
  git -C "$guard_repo" add side.txt
  git -C "$guard_repo" -c core.hooksPath=/dev/null commit -q -m 'side history edge'
  git -C "$guard_repo" checkout -q main
  printf 'main\n' > "$guard_repo/main.txt"
  git -C "$guard_repo" add main.txt
  git -C "$guard_repo" -c core.hooksPath=/dev/null commit -q -m 'main history edge'
  git -C "$guard_repo" -c core.hooksPath=/dev/null merge -q --no-ff history-edge-side -m 'merge history edge'
  (cd "$guard_repo" && "$repo_root/scripts/secret_scan.sh" --history) \
    > "$check_dir/history-guard-restored.stdout" 2> "$check_dir/history-guard-restored.stderr"
  echo "history isolation and empty, binary, merge edge self-check passed"

  probe_repo="$check_dir/repo"
  mkdir -p "$probe_repo"
  git -C "$probe_repo" init -q -b main
  git -C "$probe_repo" config user.name 'Secret Scan Probe'
  git -C "$probe_repo" config user.email 'probe@example.invalid'

  fixture_paths='docs/protocol-v1.md
spec/bap-v1.md
priv/conformance/application-profiles/local-loopback-http/v1/profile.json
priv/conformance/v2/corpus/cases/anchored-export/probe.json
priv/conformance/v1/vectors/consumption-chain-archive.json
sdks/go/conformance/corpus-v2/cases/signing-input/probe.json
sdks/rust/conformance/corpus/cases/envelope/probe.json
sdks/go/jwk_test.go
sdks/go/tests/permissiveness_test.go
sdks/rust/src/ed25519.rs
sdks/typescript/conformance/corpus-v2/cases/anchored-export/probe.json
sdks/typescript/conformance/corpus-v2/cases/grant-verify/probe.json
sdks/typescript/test/facade.test.ts
lib/non_fixture_probe.ex'
  canary_file="$check_dir/root-canaries.txt"
  : > "$canary_file"
  fixture_path_file="$check_dir/fixture-paths.txt"
  printf '%s\n' "$fixture_paths" > "$fixture_path_file"
  fixture_count=0
  old_ifs=$IFS
  IFS='
'
  for path in $fixture_paths; do
    mkdir -p "$probe_repo/$(dirname "$path")"
    canary=$(write_pat "$probe_repo/$path")
    printf '%s\n' "$canary" >> "$canary_file"
    fixture_count=$((fixture_count + 1))
  done
  IFS=$old_ifs
  python3 - "$config" "$fixture_path_file" <<'PY'
import re
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    allowlists = tomllib.load(handle).get("allowlists", [])
with open(sys.argv[2], encoding="utf-8") as handle:
    fixture_paths = [line.rstrip("\n") for line in handle]

uncovered = [
    path_regex
    for block in allowlists
    for path_regex in block.get("paths", [])
    if not any(re.fullmatch(path_regex, path) for path in fixture_paths)
]
if uncovered:
    raise SystemExit(f"allowlist path sensitivity is missing {len(uncovered)} path group(s)")
PY
  echo "allowlist path sensitivity self-check passed"
  git -C "$probe_repo" add .
  git -C "$probe_repo" -c core.hooksPath=/dev/null commit -q -m 'root sensitivity probes'
  set +e
  GIT_CONFIG_GLOBAL="$hostile_git_config" run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='--full-history --diff-merges=separate HEAD' \
    --report-format json --report-path "$check_dir/root-report.json" "$probe_repo" \
    > "$check_dir/root.stdout" 2> "$check_dir/root.stderr"
  root_exit=$?
  set -e
  while IFS= read -r root_canary; do
    assert_redacted_finding "$check_dir/root-report.json" "$check_dir/root.stdout" "$check_dir/root.stderr" "$root_canary" 'github-pat' "$root_exit"
  done < "$canary_file"
  root_count=$(grep -c '"RuleID": "github-pat"' "$check_dir/root-report.json")
  if [ "$root_count" -ne "$fixture_count" ]; then
    echo "fixture-path sensitivity expected $fixture_count findings, got $root_count" >&2
    return 1
  fi
  echo "fixture canary redaction self-check passed ($fixture_count paths)"
  echo "hostile global Git config was excluded; parser pins are unproven defensive hardening"

  generic_paths_file="$check_dir/generic-paths.txt"
  cat > "$generic_paths_file" <<'EOF'
priv/conformance/v2/corpus/cases/anchored-export/probe.json
priv/conformance/v1/vectors/consumption-chain-archive.json
sdks/go/conformance/corpus-v2/cases/signing-input/probe.json
sdks/go/jwk_test.go
sdks/go/tests/permissiveness_test.go
sdks/rust/src/ed25519.rs
sdks/typescript/conformance/corpus-v2/cases/anchored-export/probe.json
sdks/typescript/test/facade.test.ts
EOF
  generic_repo="$check_dir/generic-repo"
  mkdir -p "$generic_repo"
  git -C "$generic_repo" init -q -b main
  git -C "$generic_repo" config user.name 'Secret Scan Probe'
  git -C "$generic_repo" config user.email 'probe@example.invalid'
  printf 'clean\n' > "$generic_repo/README"
  git -C "$generic_repo" add README
  git -C "$generic_repo" -c core.hooksPath=/dev/null commit -q -m 'generic probe base'
  generic_canaries="$check_dir/generic-canaries.txt"
  : > "$generic_canaries"
  while IFS= read -r path; do
    mkdir -p "$generic_repo/$(dirname "$path")"
    value=$(write_generic_key "$generic_repo/$path")
    printf '%s\n' "$value" >> "$generic_canaries"
  done < "$generic_paths_file"
  git -C "$generic_repo" add .
  git -C "$generic_repo" -c core.hooksPath=/dev/null commit -q -m 'generic fixture-form probes'
  generic_oid=$(git --no-replace-objects -C "$generic_repo" rev-parse HEAD)
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json \
    --report-path "$check_dir/generic-report.json" "$generic_repo" \
    > "$check_dir/generic.stdout" 2> "$check_dir/generic.stderr"
  generic_exit=$?
  set -e
  if [ "$generic_exit" -ne 42 ]; then
    echo "generic fixture-form sensitivity expected exit 42, got $generic_exit" >&2
    return 1
  fi
  assert_rule_paths "$check_dir/generic-report.json" 'generic-api-key' "$generic_paths_file"
  while IFS= read -r generic_canary; do
    assert_redacted_finding "$check_dir/generic-report.json" "$check_dir/generic.stdout" "$check_dir/generic.stderr" "$generic_canary" 'generic-api-key' "$generic_exit"
  done < "$generic_canaries"
  jwt_paths_file="$check_dir/jwt-paths.txt"
  cat > "$jwt_paths_file" <<'EOF'
docs/protocol-v1.md
priv/conformance/application-profiles/local-loopback-http/v1/profile.json
priv/conformance/v2/corpus/cases/envelope/probe.json
priv/conformance/v1/vectors/grant-holder-proof.json
sdks/go/conformance/corpus-v2/cases/grant-verify/probe.json
sdks/go/permissiveness_internal_test.go
sdks/typescript/conformance/corpus-v2/cases/grant-verify/probe.json
EOF
  python3 - "$config" "$generic_paths_file" "$jwt_paths_file" <<'PY'
import re
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    allowlists = tomllib.load(handle)["allowlists"]
with open(sys.argv[2], encoding="utf-8") as handle:
    generic_paths = [line.rstrip("\n") for line in handle]
with open(sys.argv[3], encoding="utf-8") as handle:
    jwt_paths = [line.rstrip("\n") for line in handle]

for rule, paths in (("generic-api-key", generic_paths), ("jwt", jwt_paths)):
    uncovered = [
        path_regex
        for block in allowlists
        if block.get("targetRules") == [rule]
        for path_regex in block.get("paths", [])
        if not any(re.fullmatch(path_regex, path) for path in paths)
    ]
    if uncovered:
        raise SystemExit(f"{rule} fixture-form sensitivity is missing {len(uncovered)} path group(s)")
PY
  jwt_repo="$check_dir/jwt-repo"
  mkdir -p "$jwt_repo"
  git -C "$jwt_repo" init -q -b main
  git -C "$jwt_repo" config user.name 'Secret Scan Probe'
  git -C "$jwt_repo" config user.email 'probe@example.invalid'
  printf 'clean\n' > "$jwt_repo/README"
  git -C "$jwt_repo" add README
  git -C "$jwt_repo" -c core.hooksPath=/dev/null commit -q -m 'JWT probe base'
  jwt_canaries="$check_dir/jwt-canaries.txt"
  : > "$jwt_canaries"
  while IFS= read -r path; do
    mkdir -p "$jwt_repo/$(dirname "$path")"
    value=$(write_jwt "$jwt_repo/$path")
    printf '%s\n' "$value" >> "$jwt_canaries"
  done < "$jwt_paths_file"
  git -C "$jwt_repo" add .
  git -C "$jwt_repo" -c core.hooksPath=/dev/null commit -q -m 'JWT fixture-form probes'
  jwt_oid=$(git --no-replace-objects -C "$jwt_repo" rev-parse HEAD)
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json \
    --report-path "$check_dir/jwt-path-report.json" "$jwt_repo" \
    > "$check_dir/jwt-path.stdout" 2> "$check_dir/jwt-path.stderr"
  jwt_path_exit=$?
  set -e
  if [ "$jwt_path_exit" -ne 42 ]; then
    echo "JWT fixture-form sensitivity expected exit 42, got $jwt_path_exit" >&2
    return 1
  fi
  assert_rule_paths "$check_dir/jwt-path-report.json" 'jwt' "$jwt_paths_file"
  while IFS= read -r jwt_path_canary; do
    assert_redacted_finding "$check_dir/jwt-path-report.json" "$check_dir/jwt-path.stdout" "$check_dir/jwt-path.stderr" "$jwt_path_canary" 'jwt' "$jwt_path_exit"
  done < "$jwt_canaries"
  echo "targeted fixture-form sensitivity self-check passed"

  python3 - "$config" "$repo_root" "$check_dir" <<'PY'
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

config_path, repo_root, output_dir = sys.argv[1:]
with open(config_path, "rb") as handle:
    allowlists = tomllib.load(handle)["allowlists"]

def exact_literal(pattern):
    if not pattern.startswith("^") or not pattern.endswith("$"):
        raise SystemExit("fixture allowlist regex is not exactly anchored")
    body = pattern[1:-1]
    result = []
    index = 0
    metacharacters = set(".[](){}*+?|^$")
    while index < len(body):
        character = body[index]
        if character == "\\":
            index += 1
            if index == len(body):
                raise SystemExit("fixture allowlist regex ends with an escape")
            result.append(body[index])
        elif character in metacharacters:
            raise SystemExit("fixture allowlist regex is not a finite exact literal")
        else:
            result.append(character)
        index += 1
    return "".join(result)

for block, prefix in ((allowlists[0], "current-generic"), (allowlists[1], "current-jwt")):
    literal = exact_literal(block["regexes"][0])
    Path(output_dir, f"{prefix}-value.txt").write_text(literal + "\n", encoding="utf-8")

def write_historical_fixture(block, prefix):
    for pattern in block["regexes"]:
        literal = exact_literal(pattern)
        for commit in block["commits"]:
            result = subprocess.run(
                ["git", "--no-replace-objects", "-C", repo_root, "grep", "-l", "-F", "-e", literal, commit, "--"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=os.environ,
            )
            for record in result.stdout.decode("utf-8").splitlines():
                _, path = record.split(":", 1)
                if any(re.fullmatch(path_regex, path) for path_regex in block["paths"]):
                    Path(output_dir, f"{prefix}-value.txt").write_text(literal + "\n", encoding="utf-8")
                    Path(output_dir, f"{prefix}-path.txt").write_text(path + "\n", encoding="utf-8")
                    return
    raise SystemExit(f"no exact {prefix} fixture could be tied to its original path")

write_historical_fixture(allowlists[2], "historical-generic")
write_historical_fixture(allowlists[3], "historical-jwt")
PY

  exact_repo="$check_dir/exact-outside-repo"
  mkdir -p "$exact_repo/outside"
  git -C "$exact_repo" init -q -b main
  git -C "$exact_repo" config user.name 'Secret Scan Probe'
  git -C "$exact_repo" config user.email 'probe@example.invalid'
  printf 'clean\n' > "$exact_repo/README"
  git -C "$exact_repo" add README
  git -C "$exact_repo" -c core.hooksPath=/dev/null commit -q -m 'exact fixture base'
  exact_generic_paths="$check_dir/exact-generic-paths.txt"
  exact_jwt_paths="$check_dir/exact-jwt-paths.txt"
  printf '%s\n' 'outside/current-generic.txt' 'outside/historical-generic.txt' > "$exact_generic_paths"
  printf '%s\n' 'outside/current-jwt.txt' 'outside/historical-jwt.txt' > "$exact_jwt_paths"
  cp "$check_dir/current-generic-value.txt" "$exact_repo/outside/current-generic.txt"
  cp "$check_dir/current-jwt-value.txt" "$exact_repo/outside/current-jwt.txt"
  cp "$check_dir/historical-generic-value.txt" "$exact_repo/outside/historical-generic.txt"
  cp "$check_dir/historical-jwt-value.txt" "$exact_repo/outside/historical-jwt.txt"
  git -C "$exact_repo" add outside
  git -C "$exact_repo" -c core.hooksPath=/dev/null commit -q -m 'exact fixture outside allowed paths'
  exact_oid=$(git --no-replace-objects -C "$exact_repo" rev-parse HEAD)
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json \
    --report-path "$check_dir/exact-outside-report.json" "$exact_repo" \
    > "$check_dir/exact-outside.stdout" 2> "$check_dir/exact-outside.stderr"
  exact_exit=$?
  set -e
  if [ "$exact_exit" -ne 42 ]; then
    echo "exact outside-path sensitivity expected exit 42, got $exact_exit" >&2
    return 1
  fi
  assert_rule_paths "$check_dir/exact-outside-report.json" 'generic-api-key' "$exact_generic_paths"
  assert_rule_paths "$check_dir/exact-outside-report.json" 'jwt' "$exact_jwt_paths"
  for prefix in current-generic current-jwt historical-generic historical-jwt; do
    exact_value=$(cat "$check_dir/$prefix-value.txt")
    case "$prefix" in
      *generic) exact_rule='generic-api-key' ;;
      *jwt) exact_rule='jwt' ;;
    esac
    assert_redacted_finding "$check_dir/exact-outside-report.json" "$check_dir/exact-outside.stdout" "$check_dir/exact-outside.stderr" "$exact_value" "$exact_rule" "$exact_exit"
  done

  historical_repo="$check_dir/historical-new-repo"
  mkdir -p "$historical_repo"
  git -C "$historical_repo" init -q -b main
  git -C "$historical_repo" config user.name 'Secret Scan Probe'
  git -C "$historical_repo" config user.email 'probe@example.invalid'
  printf 'clean\n' > "$historical_repo/README"
  git -C "$historical_repo" add README
  git -C "$historical_repo" -c core.hooksPath=/dev/null commit -q -m 'historical fixture base'
  historical_generic_path=$(cat "$check_dir/historical-generic-path.txt")
  historical_jwt_path=$(cat "$check_dir/historical-jwt-path.txt")
  mkdir -p "$historical_repo/$(dirname "$historical_generic_path")"
  mkdir -p "$historical_repo/$(dirname "$historical_jwt_path")"
  cat "$check_dir/historical-generic-value.txt" >> "$historical_repo/$historical_generic_path"
  cat "$check_dir/historical-jwt-value.txt" >> "$historical_repo/$historical_jwt_path"
  git -C "$historical_repo" add "$historical_generic_path" "$historical_jwt_path"
  git -C "$historical_repo" -c core.hooksPath=/dev/null commit -q -m 'historical fixture in a new commit'
  historical_generic_value=$(cat "$check_dir/historical-generic-value.txt")
  historical_jwt_value=$(cat "$check_dir/historical-jwt-value.txt")
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json \
    --report-path "$check_dir/historical-new-report.json" "$historical_repo" \
    > "$check_dir/historical-new.stdout" 2> "$check_dir/historical-new.stderr"
  historical_exit=$?
  set -e
  assert_redacted_finding "$check_dir/historical-new-report.json" "$check_dir/historical-new.stdout" "$check_dir/historical-new.stderr" "$historical_generic_value" 'generic-api-key' "$historical_exit"
  assert_redacted_finding "$check_dir/historical-new-report.json" "$check_dir/historical-new.stdout" "$check_dir/historical-new.stderr" "$historical_jwt_value" 'jwt' "$historical_exit"
  python3 - "$check_dir/historical-new-report.json" "$historical_generic_path" "$historical_jwt_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    findings = json.load(handle)
expected = (("generic-api-key", sys.argv[2]), ("jwt", sys.argv[3]))
for rule, path in expected:
    if not any(finding.get("RuleID") == rule and finding.get("File") == path for finding in findings):
        raise SystemExit(f"historical {rule} fixture was not detected at its exact original path in a new commit")
PY
  echo "exact fixture path and historical-commit sensitivity self-check passed"

  python3 - "$config" "$check_dir" "$generic_oid" "$jwt_oid" "$exact_oid" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines(keepends=True)
output_dir = Path(sys.argv[2])

def remove_array(lines, block_number, key):
    result = []
    block = 0
    skipping = False
    for line in lines:
        if line.strip() == "[[allowlists]]":
            block += 1
        if not skipping and block == block_number and line.startswith(f"{key} = ["):
            skipping = True
            continue
        if skipping:
            if line.strip() == "]":
                skipping = False
            continue
        result.append(line)
    if skipping:
        raise SystemExit(f"unterminated {key} array")
    return "".join(result)

def replace_array(lines, block_number, key, replacement):
    result = []
    block = 0
    skipping = False
    replaced = 0
    for line in lines:
        if line.strip() == "[[allowlists]]":
            block += 1
        if not skipping and block == block_number and line.startswith(f"{key} = ["):
            result.append(replacement)
            skipping = True
            replaced += 1
            continue
        if skipping:
            if line.strip() == "]":
                skipping = False
            continue
        result.append(line)
    if skipping or replaced != 1:
        raise SystemExit(f"expected one complete {key} array in allowlist block {block_number}")
    return result

def remove_line(block_number, expected):
    result = []
    block = 0
    removed = 0
    for line in source:
        if line.strip() == "[[allowlists]]":
            block += 1
        if block == block_number and line.strip() == expected:
            removed += 1
            continue
        result.append(line)
    if removed != 1:
        raise SystemExit(f"expected one {expected} in allowlist block {block_number}, got {removed}")
    return "".join(result)

for block in range(1, 5):
    output_dir.joinpath(f"mutation-no-and-{block}.toml").write_text(
        remove_line(block, 'condition = "AND"'), encoding="utf-8"
    )
    output_dir.joinpath(f"mutation-no-regexes-{block}.toml").write_text(
        remove_array(source, block, "regexes"), encoding="utf-8"
    )
    output_dir.joinpath(f"mutation-no-paths-{block}.toml").write_text(
        remove_array(source, block, "paths"), encoding="utf-8"
    )
for block in (3, 4):
    output_dir.joinpath(f"mutation-no-commits-{block}.toml").write_text(
        remove_array(source, block, "commits"), encoding="utf-8"
    )

for block, oid in ((3, sys.argv[3]), (4, sys.argv[4])):
    rebound = replace_array(source, block, "commits", f'commits = ["{oid}"]\n')
    output_dir.joinpath(f"mutation-rebound-baseline-{block}.toml").write_text(
        "".join(rebound), encoding="utf-8"
    )
    output_dir.joinpath(f"mutation-rebound-no-regexes-{block}.toml").write_text(
        remove_array(rebound, block, "regexes"), encoding="utf-8"
    )
for block in (3, 4):
    rebound = replace_array(source, block, "commits", f'commits = ["{sys.argv[5]}"]\n')
    output_dir.joinpath(f"mutation-path-baseline-{block}.toml").write_text(
        "".join(rebound), encoding="utf-8"
    )
    output_dir.joinpath(f"mutation-path-no-paths-{block}.toml").write_text(
        remove_array(rebound, block, "paths"), encoding="utf-8"
    )
PY

  mutation_must_reduce() {
    mutation_config=$1
    mutation_repo=$2
    baseline_report=$3
    mutation_rule=$4
    mutation_label=$5
    mutation_report="$check_dir/$mutation_label-report.json"
    set +e
    run_gitleaks git --config "$mutation_config" --redact=100 --no-banner --exit-code 42 \
      --log-opts='HEAD^..HEAD' --report-format json --report-path "$mutation_report" \
      "$mutation_repo" > "$check_dir/$mutation_label.stdout" 2> "$check_dir/$mutation_label.stderr"
    mutation_exit=$?
    set -e
    python3 - "$baseline_report" "$mutation_report" "$mutation_exit" "$mutation_rule" "$mutation_label" <<'PY'
import json
import sys

def count(path, rule):
    with open(path, encoding="utf-8") as handle:
        return sum(finding.get("RuleID") == rule for finding in json.load(handle))

if int(sys.argv[3]) not in (0, 42):
    raise SystemExit(f"{sys.argv[5]} config scan failed with unexpected exit {sys.argv[3]}")
baseline = count(sys.argv[1], sys.argv[4])
mutated = count(sys.argv[2], sys.argv[4])
if baseline == 0 or mutated >= baseline:
    raise SystemExit(f"{sys.argv[5]} did not defeat its targeted sensitivity assertion")
PY
  }

  mutation_must_reduce "$check_dir/mutation-no-and-1.toml" "$generic_repo" "$check_dir/generic-report.json" 'generic-api-key' 'no-and-1'
  mutation_must_reduce "$check_dir/mutation-no-and-2.toml" "$jwt_repo" "$check_dir/jwt-path-report.json" 'jwt' 'no-and-2'
  mutation_must_reduce "$check_dir/mutation-no-and-3.toml" "$generic_repo" "$check_dir/generic-report.json" 'generic-api-key' 'no-and-3'
  mutation_must_reduce "$check_dir/mutation-no-and-4.toml" "$jwt_repo" "$check_dir/jwt-path-report.json" 'jwt' 'no-and-4'
  mutation_must_reduce "$check_dir/mutation-no-regexes-1.toml" "$generic_repo" "$check_dir/generic-report.json" 'generic-api-key' 'no-regexes-1'
  mutation_must_reduce "$check_dir/mutation-no-regexes-2.toml" "$jwt_repo" "$check_dir/jwt-path-report.json" 'jwt' 'no-regexes-2'
  mutation_must_reduce "$check_dir/mutation-no-paths-1.toml" "$exact_repo" "$check_dir/exact-outside-report.json" 'generic-api-key' 'no-paths-1'
  mutation_must_reduce "$check_dir/mutation-no-paths-2.toml" "$exact_repo" "$check_dir/exact-outside-report.json" 'jwt' 'no-paths-2'
  set +e
  run_gitleaks git --config "$check_dir/mutation-rebound-baseline-3.toml" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json --report-path "$check_dir/rebound-baseline-3-report.json" \
    "$generic_repo" > "$check_dir/rebound-baseline-3.stdout" 2> "$check_dir/rebound-baseline-3.stderr"
  rebound_generic_exit=$?
  run_gitleaks git --config "$check_dir/mutation-rebound-baseline-4.toml" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json --report-path "$check_dir/rebound-baseline-4-report.json" \
    "$jwt_repo" > "$check_dir/rebound-baseline-4.stdout" 2> "$check_dir/rebound-baseline-4.stderr"
  rebound_jwt_exit=$?
  run_gitleaks git --config "$check_dir/mutation-path-baseline-3.toml" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json --report-path "$check_dir/path-baseline-3-report.json" \
    "$exact_repo" > "$check_dir/path-baseline-3.stdout" 2> "$check_dir/path-baseline-3.stderr"
  path_generic_exit=$?
  run_gitleaks git --config "$check_dir/mutation-path-baseline-4.toml" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json --report-path "$check_dir/path-baseline-4-report.json" \
    "$exact_repo" > "$check_dir/path-baseline-4.stdout" 2> "$check_dir/path-baseline-4.stderr"
  path_jwt_exit=$?
  set -e
  if [ "$rebound_generic_exit" -ne 42 ] || [ "$rebound_jwt_exit" -ne 42 ] || \
    [ "$path_generic_exit" -ne 42 ] || [ "$path_jwt_exit" -ne 42 ]; then
    echo "historical rebound baseline did not detect targeted canaries" >&2
    return 1
  fi
  mutation_must_reduce "$check_dir/mutation-rebound-no-regexes-3.toml" "$generic_repo" "$check_dir/rebound-baseline-3-report.json" 'generic-api-key' 'no-regexes-3'
  mutation_must_reduce "$check_dir/mutation-rebound-no-regexes-4.toml" "$jwt_repo" "$check_dir/rebound-baseline-4-report.json" 'jwt' 'no-regexes-4'
  mutation_must_reduce "$check_dir/mutation-path-no-paths-3.toml" "$exact_repo" "$check_dir/path-baseline-3-report.json" 'generic-api-key' 'no-paths-3'
  mutation_must_reduce "$check_dir/mutation-path-no-paths-4.toml" "$exact_repo" "$check_dir/path-baseline-4-report.json" 'jwt' 'no-paths-4'
  mutation_must_reduce "$check_dir/mutation-no-commits-3.toml" "$historical_repo" "$check_dir/historical-new-report.json" 'generic-api-key' 'no-commits-3'
  mutation_must_reduce "$check_dir/mutation-no-commits-4.toml" "$historical_repo" "$check_dir/historical-new-report.json" 'jwt' 'no-commits-4'
  echo "allowlist AND, value, and path mutations passed for all blocks; commit mutations passed for both historical blocks"

  printf 'clean\n' > "$probe_repo/merge.txt"
  git -C "$probe_repo" add merge.txt
  git -C "$probe_repo" -c core.hooksPath=/dev/null commit -q -m 'merge base'
  git -C "$probe_repo" checkout -q -b merge-left
  printf 'left\n' > "$probe_repo/merge.txt"
  git -C "$probe_repo" add merge.txt
  git -C "$probe_repo" -c core.hooksPath=/dev/null commit -q -m 'left'
  git -C "$probe_repo" checkout -q main
  printf 'right\n' > "$probe_repo/merge.txt"
  git -C "$probe_repo" add merge.txt
  git -C "$probe_repo" -c core.hooksPath=/dev/null commit -q -m 'right'
  set +e
  git -C "$probe_repo" merge --no-ff merge-left -m 'merge' > "$check_dir/merge.stdout" 2> "$check_dir/merge.stderr"
  merge_exit=$?
  set -e
  if [ "$merge_exit" -eq 0 ]; then
    echo "merge sensitivity setup did not conflict" >&2
    return 1
  fi
  merge_canary=$(write_pat "$probe_repo/merge.txt")
  git -C "$probe_repo" add merge.txt
  git -C "$probe_repo" -c core.hooksPath=/dev/null commit -q -m 'merge resolution sensitivity probe'
  merge_oid=$(git --no-replace-objects -C "$probe_repo" rev-parse HEAD)
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='--full-history --diff-merges=separate HEAD' \
    --report-format json --report-path "$check_dir/merge-report.json" "$probe_repo" \
    > "$check_dir/merge-scan.stdout" 2> "$check_dir/merge-scan.stderr"
  merge_scan_exit=$?
  set -e
  assert_redacted_finding "$check_dir/merge-report.json" "$check_dir/merge-scan.stdout" "$check_dir/merge-scan.stderr" "$merge_canary" 'github-pat' "$merge_scan_exit"
  python3 - "$check_dir/merge-report.json" "$merge_oid" "$root_count" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    findings = json.load(handle)
merge_findings = [
    finding
    for finding in findings
    if finding.get("RuleID") == "github-pat"
    and finding.get("File") == "merge.txt"
    and finding.get("Commit") == sys.argv[2]
]
if not merge_findings:
    raise SystemExit("merge-resolution finding was not tied to its exact path and commit")
if len([finding for finding in findings if finding.get("RuleID") == "github-pat"]) <= int(sys.argv[3]):
    raise SystemExit("merge-aware history added no finding beyond the root probes")
PY
  echo "merge-resolution sensitivity self-check passed"

  printf 'clean\n' > "$probe_repo/index.txt"
  git -C "$probe_repo" add index.txt
  git -C "$probe_repo" -c core.hooksPath=/dev/null commit -q -m 'index base'
  index_canary=$(write_pat "$probe_repo/index.txt")
  git -C "$probe_repo" add index.txt
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 --staged \
    --report-format json --report-path "$check_dir/staged-report.json" "$probe_repo" \
    > "$check_dir/staged.stdout" 2> "$check_dir/staged.stderr"
  staged_exit=$?
  set -e
  assert_redacted_finding "$check_dir/staged-report.json" "$check_dir/staged.stdout" "$check_dir/staged.stderr" "$index_canary" 'github-pat' "$staged_exit"

  git -C "$probe_repo" restore --staged index.txt
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 --pre-commit \
    --report-format json --report-path "$check_dir/unstaged-report.json" "$probe_repo" \
    > "$check_dir/unstaged.stdout" 2> "$check_dir/unstaged.stderr"
  unstaged_exit=$?
  set -e
  assert_redacted_finding "$check_dir/unstaged-report.json" "$check_dir/unstaged.stdout" "$check_dir/unstaged.stderr" "$index_canary" 'github-pat' "$unstaged_exit"

  git -C "$probe_repo" restore index.txt
  jwt_canary=$(write_jwt "$probe_repo/lib/runtime-token.txt")
  git -C "$probe_repo" add lib/runtime-token.txt
  git -C "$probe_repo" -c core.hooksPath=/dev/null commit -q -m 'runtime JWT scope probe'
  set +e
  run_gitleaks git --config "$config" --redact=100 --no-banner --exit-code 42 \
    --log-opts='HEAD^..HEAD' --report-format json --report-path "$check_dir/jwt-report.json" \
    "$probe_repo" > "$check_dir/jwt.stdout" 2> "$check_dir/jwt.stderr"
  jwt_exit=$?
  set -e
  assert_redacted_finding "$check_dir/jwt-report.json" "$check_dir/jwt.stdout" "$check_dir/jwt.stderr" "$jwt_canary" 'jwt' "$jwt_exit"
  echo "JWT canary redaction self-check passed"

  history_scan
  echo "secret scan self-check passed"
}

case "${1:-local}" in
  --check)
    run_check
    ;;
  --history)
    require_version "$expected_version"
    history_scan
    ;;
  local)
    require_version "$expected_version"
    history_scan
    staged_scan
    unstaged_scan
    ;;
  *)
    echo "usage: scripts/secret_scan.sh [--check|--history]" >&2
    exit 1
    ;;
esac
