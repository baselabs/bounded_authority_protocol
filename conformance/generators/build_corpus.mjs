#!/usr/bin/env node
// Corpus re-derivability tool (authoring tooling — NOT a conformance runner).
//
// The v1 corpus is a frozen, certified artifact: its signed fixtures were minted with ephemeral
// in-memory Ed25519 keys at authoring time and the original throwaway mint script was removed
// (the vectors' provenance blocks record this). This tool is the RECONSTRUCTED generator,
// authored at the revision-sidecar landing: it cannot and does not re-mint fixtures. What it
// does is make every DERIVED corpus byte mechanically re-derivable and byte-verified:
//
//   - index.json is rebuilt from the frozen inputs: the cases/** files (per-file SHA-256 +
//     per-file case counts + the applicability matrix), the revision sidecar, and the curated
//     inputs this directory ships (n_a cell reasons + the public-key fingerprint census —
//     prose and census facts that are inputs to the index, not derivable from case bytes).
//   - revision.json carries the monotone corpus revision; --bump-revision is the amendment
//     path (rotate the six certified-index-SHA pins in the SAME commit with
//     scripts/regen_corpus_digests.exs --write — the ADR 0019 atomic-landing template).
//   - --verify proves the shipped corpus equals the rebuild byte-for-byte (and that every
//     tamper case's verbatim bytes equal base-with-one-flip re-derived from its base case).
//
// Usage:
//   node conformance/generators/build_corpus.mjs --verify [--corpus DIR]
//   node conformance/generators/build_corpus.mjs --rebuild-index [--corpus DIR]   # requires revision.json
//   node conformance/generators/build_corpus.mjs --bump-revision --note TEXT [--corpus DIR]
//
// DIR defaults to priv/conformance/v1/corpus (repo-relative).

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const REPO_ROOT = join(import.meta.dirname, "..", "..");
const DEFAULT_CORPUS = join(REPO_ROOT, "priv", "conformance/v1/corpus");
const CURATED_PATH = join(import.meta.dirname, "curated-inputs.json");

const INDEX_FORMAT = "bounded-authority-protocol-v1-conformance-corpus-index";
const CASES_FORMAT = "bounded-authority-protocol-v1-conformance-cases";
const REVISION_FORMAT = "bounded-authority-protocol-v1-conformance-corpus-revision";
const REVISION_PATH = "revision.json";

const SURFACES = [
  "untrusted_key_locator", "grant_signing_input", "proof_signing_input",
  "encode_consumption_entry", "check_chain", "boundary_anchor_signing_input",
  "key_transition_signing_input", "encode_anchored_export", "assemble_compact",
  "decode_grant", "decode_proof", "verify_grant", "verify_historical_anchor",
  "verify_key_transition", "verify_anchored_export", "check_envelope",
  "request_digest", "jcs.encode", "jwk.encode_public", "jwk.decode_public",
  "jwk.thumbprint_preimage", "jwk.thumbprint", "jwk.thumbprint_raw",
  "jwk.public_key_thumbprint_raw", "uri.normalize", "json.decode",
  "base64url.decode", "bounds.new",
];
const CLASSES = [
  "valid", "boundary_near", "exact_bound", "maximum_plus_one",
  "invalid_duplicate", "invalid_encoding", "invalid_algorithm", "invalid_key",
  "invalid_claim", "invalid_time", "invalid_nonce", "invalid_uri",
  "invalid_request", "invalid_selector", "invalid_limit", "tamper_meaningful_byte",
];

function fail(message) {
  console.error(`build_corpus: ${message}`);
  process.exit(1);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256B64u(bytes) {
  return createHash("sha256").update(bytes).digest("base64url");
}

function listFiles(dir) {
  const out = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const full = join(current, name);
      if (statSync(full).isDirectory()) walk(full);
      else out.push(full);
    }
  };
  walk(dir);
  return out;
}

function parseArgs(argv) {
  const args = { corpus: DEFAULT_CORPUS };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--corpus") args.corpus = argv[++i];
    else if (a === "--verify") args.mode = "verify";
    else if (a === "--rebuild-index") args.mode = "rebuild";
    else if (a === "--bump-revision") args.mode = "bump";
    else if (a === "--note") args.note = argv[++i];
    else fail(`unknown argument ${a}`);
  }
  if (!args.mode) fail("one of --verify | --rebuild-index | --bump-revision is required");
  if (args.mode === "bump" && !args.note) fail("--bump-revision requires --note");
  return args;
}

// ---- frozen inputs ----------------------------------------------------------

function loadCases(corpusDir) {
  const casesByPath = new Map();
  const files = listFiles(corpusDir)
    .map((abs) => relative(corpusDir, abs).split(sep).join("/"))
    .filter((rel) => rel !== "index.json" && rel !== REVISION_PATH);
  for (const rel of files) {
    const bytes = readFileSync(join(corpusDir, rel));
    casesByPath.set(rel, bytes);
  }
  return casesByPath;
}

function caseMeta(rel, bytes) {
  if (rel.endsWith(".raw")) return { cases: 0 };
  const parsed = JSON.parse(bytes.toString("utf8"));
  if (parsed.format !== CASES_FORMAT) fail(`${rel}: not a case file (${parsed.format})`);
  return { cases: parsed.cases.length, parsed };
}

function applicability(casesByPath, naReasons) {
  const counts = {};
  for (const surface of SURFACES) {
    counts[surface] = {};
    for (const cls of CLASSES) counts[surface][cls] = 0;
  }
  for (const [rel, bytes] of casesByPath) {
    if (rel.endsWith(".raw")) continue;
    const { parsed } = caseMeta(rel, bytes);
    for (const c of parsed.cases) {
      if (!(c.surface in counts) || !(c.class in counts[c.surface])) {
        fail(`${rel}: unknown surface/class ${c.surface}/${c.class}`);
      }
      counts[c.surface][c.class] += 1;
    }
  }
  const matrix = {};
  for (const surface of SURFACES) {
    matrix[surface] = {};
    for (const cls of CLASSES) {
      const n = counts[surface][cls];
      if (n > 0) matrix[surface][cls] = n;
      else {
        const reason = naReasons?.[surface]?.[cls];
        if (reason === undefined) fail(`n_a cell ${surface}/${cls} has no curated reason`);
        matrix[surface][cls] = { n_a: reason };
      }
    }
  }
  return matrix;
}

function buildIndex(corpusDir, casesByPath, curated, revisionBytes) {
  const files = [...casesByPath.entries()]
    .map(([rel, bytes]) => ({
      path: rel,
      sha256_base64url: sha256B64u(bytes),
      cases: caseMeta(rel, bytes).cases,
    }));
  files.push({
    path: REVISION_PATH,
    sha256_base64url: sha256B64u(revisionBytes),
    cases: 0,
  });
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return {
    format: INDEX_FORMAT,
    public_key_fingerprints: curated.public_key_fingerprints,
    files,
    total_cases: files.reduce((acc, f) => acc + f.cases, 0),
    applicability: applicability(casesByPath, curated.applicability_n_a_reasons),
  };
}

// ---- revision sidecar -------------------------------------------------------

function revisionBytes(corpusDir) {
  const path = join(corpusDir, REVISION_PATH);
  const bytes = readFileSync(path);
  const parsed = JSON.parse(bytes.toString("utf8"));
  if (parsed.format !== REVISION_FORMAT) fail(`${REVISION_PATH}: bad format`);
  if (!Number.isInteger(parsed.revision) || parsed.revision < 1) fail(`${REVISION_PATH}: bad revision`);
  return bytes;
}

// Every tamper case's verbatim artifact must equal its base case with exactly the documented
// byte flipped (target resolution mirrors the loaders' tamper audit).
function verifyTampers(casesByPath) {
  const byId = new Map();
  for (const [rel, bytes] of casesByPath) {
    if (rel.endsWith(".raw")) continue;
    for (const c of caseMeta(rel, bytes).parsed.cases) byId.set(c.id, c);
  }
  let checked = 0;
  for (const c of byId.values()) {
    if (!c.tamper) continue;
    const base = byId.get(c.tamper.base_case);
    if (!base) fail(`tamper case ${c.id}: missing base ${c.tamper.base_case}`);
    const target = c.tamper.target ?? (c.input.text !== undefined ? "input.text" : "input.base64url");
    const baseBytes = targetBytes(base.input, target);
    const verbatimBytes = targetBytes(c.input, target);
    const { byte_index: index, xor } = c.tamper;
    if (!Number.isInteger(index) || index < 0 || index >= baseBytes.length) {
      fail(`tamper case ${c.id}: byte_index out of range`);
    }
    const derived = Buffer.from(baseBytes);
    derived[index] ^= xor;
    if (!derived.equals(verbatimBytes)) fail(`tamper case ${c.id}: verbatim != derived`);
    checked += 1;
  }
  return checked;
}

function targetBytes(input, target) {
  if (target === "input.text") return Buffer.from(input.text, "utf8");
  if (target === "input.base64url") return Buffer.from(input.base64url, "base64url");
  if (["compact", "grant", "proof"].includes(target)) return Buffer.from(input[target], "utf8");
  const rows = target.match(/^(rows|chunks)\[(\d+)\]$/);
  if (rows) {
    const element = input[rows[1]][Number(rows[2])];
    if (typeof element !== "string") fail(`tamper target ${target}: not a string element`);
    return Buffer.from(element, "base64url");
  }
  fail(`tamper target ${target}: unknown`);
}

// ---- modes ------------------------------------------------------------------

function main() {
  const args = parseArgs(process.argv.slice(2));
  const curated = JSON.parse(readFileSync(CURATED_PATH, "utf8"));
  const casesByPath = loadCases(args.corpus);

  if (args.mode === "bump") {
    const current = JSON.parse(revisionBytes(args.corpus).toString("utf8"));
    const sidecar = {
      format: REVISION_FORMAT,
      revision: current.revision + 1,
      generated_from: args.note,
    };
    writeFileSync(join(args.corpus, REVISION_PATH), canonical(sidecar));
  }

  const revBytes = revisionBytes(args.corpus);
  const index = buildIndex(args.corpus, casesByPath, curated, revBytes);
  const rebuilt = canonical(index);

  if (args.mode === "rebuild" || args.mode === "bump") {
    writeFileSync(join(args.corpus, "index.json"), rebuilt);
    console.log(`build_corpus: rebuilt index.json (total_cases=${index.total_cases}, files=${index.files.length})`);
    return;
  }

  // --verify: shipped corpus must equal the rebuild byte-for-byte.
  const shipped = readFileSync(join(args.corpus, "index.json"));
  if (!shipped.equals(Buffer.from(rebuilt, "utf8"))) {
    fail("index.json does not equal the rebuild (corpus or curated inputs drifted)");
  }
  const tampers = verifyTampers(casesByPath);
  const revision = JSON.parse(revBytes.toString("utf8")).revision;
  console.log(
    `build_corpus: verify ok (files=${index.files.length}, total_cases=${index.total_cases}, ` +
      `revision=${revision}, tampers=${tampers})`,
  );
}

main();
