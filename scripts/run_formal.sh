#!/usr/bin/env bash
set -euo pipefail

# Formal-analysis re-run (spec/formal/README.md): pinned ProVerif execution + three checks.
#
#   1. run the model and diff the RESULT lines against spec/formal/expected-summary.txt
#      (non-regression: a model edit changing any verdict line reds);
#   2. REQ-id coverage: every REQ1-* annotation in the model exists in the requirement map;
#   3. findings ledger: every F<n> entry in spec/formal/FINDINGS.md carries exactly one
#      terminal disposition (refuted | documented | escalated).
#
# Any escalated disposition is printed loudly: it blocks the program's done-claim until the
# owner rules (routed via SECURITY.md).
script_dir=$(dirname "$0")
cd "$script_dir/.."

MODEL=spec/formal/proverif/bap-core.pv
SUMMARY=spec/formal/expected-summary.txt
LEDGER=spec/formal/FINDINGS.md
MAP=docs/design/requirement-map.md

fail=0

if ! command -v proverif >/dev/null 2>&1; then
  # The mix-quality invocation is optionally-skippable (the toolchain is opam-local and the
  # dedicated CI formal job is the fail-closed enforcement); a direct invocation fails closed.
  if [ "${BAP_FORMAL_OPTIONAL:-0}" = 1 ]; then
    echo "run_formal: SKIP: proverif not found (opam pin proverif.2.05); the CI formal-analysis job enforces this run"
    exit 0
  fi
  echo "run_formal: proverif not found (opam pin proverif.2.05; spec/formal/README.md)" >&2
  exit 2
fi

# --- 1. non-regression summary diff -------------------------------------------
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/bap-formal-results.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
results="$work_dir/results"
proverif "$MODEL" > "$work_dir/output" 2>&1
grep -E '^RESULT' "$work_dir/output" > "$results" || [ "$?" -eq 1 ]
expected=$(grep -E '^RESULT' "$SUMMARY")
actual=$(cat "$results")

if [ "$expected" != "$actual" ]; then
  echo "run_formal: FAILED: model output diverges from the frozen summary:" >&2
  printf '%s\n' "$expected" > "$work_dir/expected"
  diff "$work_dir/expected" "$results" >&2 || [ "$?" -eq 1 ]
  fail=1
else
  true_count=$(grep -c 'is true' "$results") || [ "$?" -eq 1 ]
  query_count=$(wc -l < "$results" | tr -d ' ')
  echo "run_formal: summary ok ($true_count/$query_count queries true)"
  if grep 'cannot be proved' "$results" >/dev/null; then
    echo "run_formal: FAILED: at least one query is NOT proved" >&2
    fail=1
  else
    [ "$?" -eq 1 ]
  fi
fi

# --- 2. REQ-id coverage --------------------------------------------------------
map_ids=$(grep -o 'REQ1-[A-Z0-9]*-[a-z0-9-]*' "$MAP" | sort -u)
# The pinned annotation set: the verifier steps whose requirement mapping is load-bearing for
# the model's claims. Dropping an annotation reds; adding a mapped one is fine.
PINNED="REQ1-CLAIM-ath REQ1-SIGNING-backend-reject REQ1-SIGNING-digest-prefix
REQ1-HEADER-thumbprint REQ1-HEADER-proof-jwk REQ1-VERIFY-grant-exact
REQ1-VERIFY-envelope-binding REQ1-VERIFY-facts-redacted REQ1-VERIFY-return-shape
REQ1-VERIFY-time-bounds REQ1-CLAIM-case-sensitive"
missing=0
model_ids=$(grep -o 'REQ1-[A-Z0-9]*-[a-z0-9-]*' "$MODEL" | sort -u)
for id in $model_ids; do
  if grep -x "$id" <<< "$map_ids" >/dev/null; then
    continue
  else
    [ "$?" -eq 1 ]
    echo "run_formal: FAILED: model annotates $id which is not in the requirement map" >&2
    missing=1
  fi
done
# Exact step-annotation form "(* <id> *)"; declaration prose that merely mentions ids does
# not satisfy the pin; the annotation must ride a code line.
for id in $PINNED; do
  if grep "(\* $id \*)" "$MODEL" >/dev/null; then
    continue
  else
    [ "$?" -eq 1 ]
    echo "run_formal: FAILED: pinned annotation $id dropped from the model" >&2
    missing=1
  fi
done
if [ "$missing" = 0 ]; then
  annotation_count=$(printf '%s\n' "$model_ids" | wc -l | tr -d ' ')
  echo "run_formal: coverage ok ($annotation_count annotated ids all mapped; pinned set intact)"
fi

# --- 3. findings ledger schema --------------------------------------------------
python3 - "$LEDGER" <<'PYEOF'
import re, sys
text = open(sys.argv[1]).read()
entries = re.findall(r'^## F\d+:.*?(?=^## |\Z)', text, re.S | re.M)
problems = []
escalated = 0
for e in entries:
    m = re.search(r'^- disposition:\s*(\w+)', e, re.M)
    if not m:
        problems.append("entry without disposition line: " + e.split("\n")[0])
    elif m.group(1) not in ("refuted", "documented", "escalated"):
        problems.append("non-terminal disposition: " + m.group(1))
    if m and m.group(1) == "escalated":
        escalated += 1
if problems:
    print("run_formal: FAILED: ledger schema violations:\n  " + "\n  ".join(problems), file=sys.stderr)
    sys.exit(1)
print(f"run_formal: ledger ok ({len(entries)} findings, all terminally dispositioned, {escalated} escalated)")
if escalated:
    print(f"run_formal: *** {escalated} ESCALATED finding(s): BLOCKS the program done-claim until the owner rules (SECURITY.md routing) ***", file=sys.stderr)
PYEOF

exit $((fail + missing))
