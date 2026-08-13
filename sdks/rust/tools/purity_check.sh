#!/bin/sh
# BAP-15 Task 16 — enforce the lib-path purity invariant.
#
# AGENTS rule 2 + ADR 0014 D8: the library path under src/ must contain no I/O,
# filesystem, network, process-spawn, environment, wall/monotonic clock, or RNG.
# These are SAFE Rust APIs that #![forbid(unsafe_code)] does NOT catch, so a
# grep is the enforcement. Test modules (#[cfg(test)]) are stripped before the
# scan — the corpus loaders under tests legitimately read corpus files; only the
# non-test lib path is purity-bound.
#
# `unsafe` is enforced separately by the crate-level #![forbid(unsafe_code)]
# (a planted `unsafe {}` block fails `cargo build` — that is the red-capable
# proof for the unsafe half). It is intentionally NOT grep-checked here: several
# src/ doc comments legitimately name the forbid policy, so a bare-`unsafe` grep
# would false-positive on the very prose that documents the invariant.
#
# Exits 0 if the lib path is pure, 1 on any forbidden API. Adversarially probed
# red-capable: planting `use std::fs;` in a src/ lib path makes this script
# exit 1; removing it restores exit 0.

set -eu

src_dir=$(cd "$(dirname "$0")/.." && pwd)/src

# Safe-but-impure APIs that #![forbid(unsafe_code)] does not catch.
# `rand::` / `rand_core::` are path-qualified to avoid the doc-comment mention
# of `rand_core` (features) in src/ed25519.rs. The bare tokens `HashSet` /
# `HashMap` match the default `RandomState::new()` collections (whose constructor
# reads OS entropy via hashmap_random_keys — a randomness boundary this pure
# library forbids; use `BTreeSet`/`BTreeMap`) in ANY spelling — fully-qualified,
# brace-import (`use std::collections::{HashSet, …}`), or bare. The src/ comments
# that document this choice are worded to avoid the bare tokens, so the grep does
# not false-positive on its own prose.
patterns='std::fs|std::net|std::process|std::env|std::io|std::time::SystemTime|std::time::Instant|getrandom|rand::|rand_core::|HashSet|HashMap'

status=0
# find -print0 / read -d '' is not POSIX; src/ is flat, so a plain glob suffices
# and stays portable. The glob always matches (src/ has .rs files).
for f in "$src_dir"/*.rs; do
  # Strip the trailing #[cfg(test)] module (test code reads corpus files).
  lib_path=$(awk '/^#\[.*cfg\(test\)/{exit} {print}' "$f")
  if printf '%s\n' "$lib_path" | grep -En "$patterns" >/dev/null 2>&1; then
    echo "purity_check: FAIL — forbidden API in lib path of ${f##*/}:" >&2
    printf '%s\n' "$lib_path" | grep -En "$patterns" >&2 || true
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "purity_check: OK — no I/O / clock / RNG / network / env API in src/ lib path."
