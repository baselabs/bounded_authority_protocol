#!/usr/bin/env node
// Producer-canonicality corpus generator (authoring tooling; NOT a conformance runner; not in the
// Hex package, whose `files` list does not include conformance/).
//
// Writes the additive corpus priv/conformance/producer-canonicality/ (profile
// `bap-producer-canonicality/1`, erratum 3): profile.json, revision.json, cases/<family>/*.json and
// index.json. Existing certified corpora are read only as TEMPLATES (one valid compact per signing
// kind, and the valid anchored-export encode inputs); none is written.
//
// The corpus certifies the producer surfaces: compact assembly and anchored-export encoding frame a
// signature and verify none, and each MUST refuse a signature that no conforming signer emits while
// emitting every accepted signature's bytes unchanged.
//
//   - ES256 (contract-major 3): `0 < r < n` and `0 < s <= floor(n/2)` (spec/bap-v3.md section 3.2).
//   - Ed25519 (contract-majors 1 and 2, local loopback, role attestation, content assertion): the
//     keyless part of rule S1: R canonical (y < p, and no sign bit when x = 0), R not of small
//     order, and S < L (spec/bap-v1.md section 16).
//
// The generator is keyless. Every derived signature comes from BigInt arithmetic on a certified
// signature (no signing, no key, no randomness).
//
// Expected verdicts. Every verdict comes from the rule text in pure BigInt arithmetic: the ES256
// scalars compared with n and floor(n/2) as integers; the Ed25519 R classified by the strict
// RFC 8032 section 5.1.3 decode and the order test [8]R == O (strict_ed25519_reference.mjs), and S
// compared with L as an integer. There is no table and no backend in the verdict path.
//
// Cross-check (fails generation on any disagreement). Every verdict is recomputed independently
// from bytes: the ES256 scalars as fixed-width lowercase hex compared lexicographically with the
// hex of n and floor(n/2); the Ed25519 R by a byte-level canonical test and the literal 8-entry
// small-order table, and S by comparing its big-endian hex with that of L. Each case's verdict must
// also equal the verdict its construction intends. Every template signature must pass the rule;
// every natural high-S counterpart must verify under node:crypto P1363 ECDSA (proof that the
// counterpart is a real signature that only the low-S rule refuses).
//
// Determinism. No randomness and a fixed iteration order; output is canonical JSON, so every run is
// byte-identical (`--verify` rebuilds and compares every shipped byte).
//
// Usage:
//   node conformance/generators/build_producer_canonicality.mjs            # (re)write the corpus
//   node conformance/generators/build_producer_canonicality.mjs --verify   # shipped == rebuild
//   ... [--out DIR] [--repo-root DIR]                                       # alternate output / templates

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import * as Ref from "./strict_ed25519_reference.mjs";

const PROFILE = "bap-producer-canonicality/1";
const REVISION = 1;
const GENERATOR_PATH = "conformance/generators/build_producer_canonicality.mjs";
const FORMAT_CASES = "bounded-authority-protocol-producer-canonicality-conformance-cases";
const FORMAT_INDEX = "bounded-authority-protocol-producer-canonicality-conformance-corpus-index";
const FORMAT_PROFILE = "bounded-authority-protocol-producer-canonicality-conformance-profile";
const FORMAT_REVISION = "bounded-authority-protocol-producer-canonicality-conformance-corpus-revision";

const RULE_ES256 = "REQ3-SIGNING-producer-canonical";
const RULE_ED25519 = { 1: "REQ1-SIGNING-ed25519-producer-canonical", 2: "REQ2-SIGNING-ed25519-producer-canonical" };
const PROFILE_LOOPBACK = "bap-application-proof/local-loopback-http/1";
const PROFILE_RA1 = "bap-role-attestation/1";
const PROFILE_CA1 = "bap-content-assertion/1";
const PROFILE_RULES = {
  [PROFILE_LOOPBACK]: "REQ-LLH1-API-assembly-revalidate",
  [PROFILE_RA1]: "REQ-RA1-API-assembly-revalidate",
  [PROFILE_CA1]: "REQ-CA1-API-assembly",
};

// Every case file must load through the reference JSON decoder at Bounds.maximum().
const LIMITS = { json_bytes: 65536, total_nodes: 4096, depth: 32, object_members: 64, array_items: 256, string_bytes: 8192, key_bytes: 128 };
const FILE_BUDGET = { bytes: 60000, nodes: 3600, cases: 256 };

// ---- arguments ------------------------------------------------------------------------------

function fail(message) {
  console.error(`build_producer_canonicality: ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { mode: "write", repoRoot: join(import.meta.dirname, "..", "..") };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--verify") args.mode = "verify";
    else if (a === "--out") args.out = argv[++i];
    else if (a === "--repo-root") args.repoRoot = argv[++i];
    else fail(`unknown argument ${a}`);
  }
  if (!args.out) args.out = join(args.repoRoot, "priv", "conformance", "producer-canonicality");
  return args;
}

const ARGS = parseArgs(process.argv.slice(2));
const REPO = ARGS.repoRoot;

// ---- encoding utilities ---------------------------------------------------------------------

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail(`non-integer or unsafe number ${value}`);
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  fail(`cannot canonicalize ${typeof value}`);
}

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const fromB64u = (text) => {
  const bytes = Buffer.from(text, "base64url");
  if (b64u(bytes) !== text) fail(`non-canonical base64url ${text.slice(0, 16)}...`);
  return bytes;
};
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest();

function bigToBe(value, width) {
  const text = value.toString(16).padStart(width * 2, "0");
  if (text.length !== width * 2) fail("value does not fit width");
  return Buffer.from(text, "hex");
}

const beToBig = (bytes) => BigInt(`0x${hex(bytes) || "0"}`);

function splitCompact(compact) {
  const parts = compact.split(".");
  if (parts.length !== 3) fail("template compact does not have three segments");
  const signature = fromB64u(parts[2]);
  if (signature.length !== 64) fail("template signature is not 64 bytes");
  return { protected: parts[0], payload: parts[1], signature };
}

const withSignature = (compact, signature) => {
  const { protected: p, payload } = splitCompact(compact);
  return `${p}.${payload}.${b64u(signature)}`;
};

function readJson(...path) {
  return JSON.parse(readFileSync(join(REPO, ...path), "utf8"));
}

function casesOf(doc) {
  return Array.isArray(doc) ? doc : doc.cases;
}

function firstCase(path, predicate, label) {
  const found = casesOf(readJson(...path)).find(predicate);
  if (!found) fail(`no template case for ${label} in ${path.join("/")}`);
  return found;
}

const validVerdict = (c) => c.expected && c.expected.verdict === "valid";

// ---- ES256 (contract-major 3) ---------------------------------------------------------------

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N / 2n;

// Verdict: the rule text in integer arithmetic.
function es256Verdict(signature) {
  const r = beToBig(signature.subarray(0, 32));
  const s = beToBig(signature.subarray(32));
  return r > 0n && r < N && s > 0n && s <= HALF_N;
}

// Cross-check: fixed-width lowercase hex compared lexicographically (equal width, so the order is
// the numeric order) against literal hex constants, with zero as the all-zero string.
const N_HEX = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const HALF_N_HEX = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";
const ZERO_HEX = "0".repeat(64);

function es256CrossCheck(signature) {
  const r = hex(signature.subarray(0, 32));
  const s = hex(signature.subarray(32));
  return r !== ZERO_HEX && r < N_HEX && s !== ZERO_HEX && s <= HALF_N_HEX;
}

if (bigToBe(N, 32).toString("hex") !== N_HEX || bigToBe(HALF_N, 32).toString("hex") !== HALF_N_HEX) {
  fail("ES256 cross-check constants disagree with the BigInt order");
}

function p256Key(raw) {
  if (raw.length !== 65 || raw[0] !== 0x04) fail("template P-256 key is not uncompressed SEC1");
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(raw.subarray(1, 33)), y: b64u(raw.subarray(33)) }, format: "jwk" });
}

function p256KeyFromJwk(jwk) {
  return createPublicKey({ key: { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
}

const p1363 = (message, signature, key) =>
  nodeVerify("sha256", Buffer.from(message, "ascii"), { key, dsaEncoding: "ieee-p1363" }, signature);

// ---- Ed25519 (keyless part of rule S1) ------------------------------------------------------

// Verdict: R by the strict decode and [8]R == O; S as an integer below L.
function ed25519Verdict(signature) {
  const r = Ref.classifyEncoding(Buffer.from(signature.subarray(0, 32)));
  if (r.kind === "noncanonical") return false;
  if (r.kind === "point" && Ref.isSmallOrder(r.point)) return false;
  return Ref.leToBig(signature.subarray(32)) < Ref.L;
}

// Cross-check: the byte-level canonical test, the literal small-order table, and S compared with L
// as big-endian hex.
const SMALL_ORDER_HEX = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
];
const P_MINUS_ONE_BE_HEX = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec";
const P_BE_HEX = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
const ONE_BE_HEX = `${"0".repeat(62)}01`;
const L_BE_HEX = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

const beHex = (le) => hex(Buffer.from(le).reverse());

function ed25519CrossCheck(signature) {
  const r = Buffer.from(signature.subarray(0, 32));
  const sign = (r[31] & 0x80) !== 0;
  const yBytes = Buffer.from(r);
  yBytes[31] &= 0x7f;
  const y = beHex(yBytes);
  const canonicalR = y < P_BE_HEX && !(sign && (y === ONE_BE_HEX || y === P_MINUS_ONE_BE_HEX));
  const smallOrder = SMALL_ORDER_HEX.includes(hex(r));
  return canonicalR && !smallOrder && beHex(signature.subarray(32)) < L_BE_HEX;
}

if (beHex(Ref.bigToLe(Ref.L, 32)) !== L_BE_HEX || beHex(Ref.bigToLe(Ref.P, 32)) !== P_BE_HEX) {
  fail("Ed25519 cross-check constants disagree with the BigInt reference");
}

const IDENTITY_R = Ref.bigToLe(1n, 32);
const NONCANONICAL_R = Ref.bigToLe(Ref.P, 32); // y = p, little-endian: a non-canonical encoding of y = 0

// ---- case construction ----------------------------------------------------------------------

const disagreements = [];
const stats = { checked: 0, templates: 0, highSNodeVerified: 0 };

function judge(id, suite, signature, intent) {
  const verdict = suite === "es256" ? es256Verdict(signature) : ed25519Verdict(signature);
  const cross = suite === "es256" ? es256CrossCheck(signature) : ed25519CrossCheck(signature);
  stats.checked += 1;
  if (verdict !== cross) disagreements.push(`${id}: BigInt verdict ${verdict}, cross-check ${cross}`);
  if (verdict !== (intent === "valid")) disagreements.push(`${id}: verdict ${verdict}, construction intends ${intent}`);
  return verdict;
}

function assertTemplate(label, suite, signature) {
  stats.templates += 1;
  judge(`template ${label}`, suite, signature, "valid");
}

function assembleCase({ id, rule, major, profile, kind, compact, signature, intent, construction }) {
  const { protected: p, payload } = splitCompact(compact);
  const suite = major === 3 ? "es256" : "ed25519";
  const valid = judge(id, suite, signature, intent);
  const input = { payload_segment: payload, protected_segment: p, signature: b64u(signature) };
  if (kind) input.kind = kind;
  const c = {
    class: valid ? "exact_bound" : "invalid_encoding",
    construction,
    expected: valid ? { compact: `${p}.${payload}.${b64u(signature)}`, verdict: "valid" } : { verdict: "invalid" },
    id,
    input,
    rule,
    surface: "assemble_compact",
  };
  if (major !== undefined) c.major = major;
  if (profile !== undefined) c.profile = profile;
  return c;
}

// ---- ES256 families --------------------------------------------------------------------------

function es256Templates() {
  const dir = ["priv", "conformance", "v3", "corpus", "cases"];
  const grant = firstCase([...dir, "grant-verify", "verify.json"], validVerdict, "v3 grant");
  const envelope = firstCase([...dir, "envelope", "check.json"], validVerdict, "v3 proof");
  const anchor = firstCase([...dir, "boundary-anchor", "verify.json"], validVerdict, "v3 anchor");
  const transition = firstCase([...dir, "key-transition", "verify.json"], validVerdict, "v3 transition");
  const proofHeader = JSON.parse(fromB64u(envelope.input.proof.split(".")[0]).toString("utf8"));
  return [
    { kind: "grant", compact: grant.input.compact, key: p256Key(fromB64u(grant.input.public_key)) },
    { kind: "proof", compact: envelope.input.proof, key: p256KeyFromJwk(proofHeader.jwk) },
    { kind: "boundary_anchor", compact: anchor.input.compact, key: p256Key(fromB64u(anchor.input.key.public_key)) },
    { kind: "key_transition", compact: transition.input.compact, key: p256Key(fromB64u(transition.input.current_key.public_key)) },
  ];
}

const es256Sig = (r, s) => Buffer.concat([bigToBe(r, 32), bigToBe(s, 32)]);

function familyEs256Assemble() {
  const cases = [];
  for (const t of es256Templates()) {
    const { protected: p, payload, signature } = splitCompact(t.compact);
    assertTemplate(`v3 ${t.kind}`, "es256", signature);
    const message = `${p}.${payload}`;
    if (!p1363(message, signature, t.key)) fail(`v3 ${t.kind}: the template signature does not verify`);
    const r = beToBig(signature.subarray(0, 32));
    const s = beToBig(signature.subarray(32));
    const highS = es256Sig(r, N - s);
    if (!p1363(message, highS, t.key)) fail(`v3 ${t.kind}: the high-S counterpart does not verify under ECDSA`);
    stats.highSNodeVerified += 1;
    const variants = [
      ["r-zero", es256Sig(0n, s), "invalid", "r = 0"],
      ["r-equals-n", es256Sig(N, s), "invalid", "r = n"],
      ["s-zero", es256Sig(r, 0n), "invalid", "s = 0"],
      ["s-half-order-plus-one", es256Sig(r, HALF_N + 1n), "invalid", "s = floor(n/2) + 1"],
      ["s-half-order", es256Sig(r, HALF_N), "valid", "s = floor(n/2), emitted unchanged"],
      ["high-s", highS, "invalid", "(r, n - s) of the certified signature; verifies under raw ECDSA"],
    ];
    for (const [label, sig, intent, signatureNote] of variants) {
      cases.push(
        assembleCase({
          id: `assemble-v3-${t.kind.replaceAll("_", "-")}-${label}`,
          rule: RULE_ES256,
          major: 3,
          kind: t.kind,
          compact: t.compact,
          signature: sig,
          intent,
          construction: { signature: signatureNote, template: `certified v3 ${t.kind}` },
        }),
      );
    }
  }
  return cases;
}

function exportTemplate(major) {
  return firstCase(["priv", "conformance", `v${major}`, "corpus", "cases", "anchored-export", "encode.json"], validVerdict, `v${major} export`);
}

function exportCase({ id, rule, major, template, position, mutate, suite, construction }) {
  const input = structuredClone(template.input);
  const original = position === "transition" ? input.transitions[0] : input[position];
  const { signature } = splitCompact(original);
  assertTemplate(`${id} template`, suite, signature);
  const replaced = mutate(signature);
  judge(id, suite, replaced, "invalid");
  const compact = withSignature(original, replaced);
  if (position === "transition") input.transitions[0] = compact;
  else input[position] = compact;
  return { class: "invalid_encoding", construction, expected: { verdict: "invalid" }, id, input, major, rule, surface: "encode_anchored_export" };
}

function familyEs256Export() {
  const template = exportTemplate(3);
  const highS = (signature) => es256Sig(beToBig(signature.subarray(0, 32)), N - beToBig(signature.subarray(32)));
  return [
    ["start_anchor", "start-anchor-high-s"],
    ["end_anchor", "end-anchor-high-s"],
    ["transition", "transition-high-s"],
  ].map(([position, label]) =>
    exportCase({
      id: `encode-anchored-export-v3-${label}`,
      rule: RULE_ES256,
      major: 3,
      template,
      position,
      mutate: highS,
      suite: "es256",
      construction: { signature: `(r, n - s) of the certified ${position.replaceAll("_", " ")} signature`, template: template.id },
    }),
  );
}

// ---- Ed25519 families ------------------------------------------------------------------------

function ed25519Templates() {
  const out = [];
  for (const major of [1, 2]) {
    const dir = ["priv", "conformance", `v${major}`, "corpus", "cases"];
    const grant = firstCase([...dir, "grant-verify", "verify.json"], validVerdict, `v${major} grant`);
    const envelope = firstCase([...dir, "envelope", "check.json"], validVerdict, `v${major} proof`);
    const anchor = firstCase([...dir, "boundary-anchor", "verify.json"], validVerdict, `v${major} anchor`);
    const transition = firstCase([...dir, "key-transition", "verify.json"], validVerdict, `v${major} transition`);
    out.push(
      { major, kind: "grant", compact: grant.input.compact },
      { major, kind: "proof", compact: envelope.input.proof },
      { major, kind: "boundary_anchor", compact: anchor.input.compact },
      { major, kind: "key_transition", compact: transition.input.compact },
    );
  }
  const loopback = firstCase(
    ["priv", "conformance", "application-profiles", "local-loopback-http", "v1", "proof-cases.json"],
    (c) => c.decode_local === true && c.envelope_local === true,
    "loopback proof",
  );
  const ra1 = firstCase(
    ["priv", "conformance", "attestation-profiles", "role-attestation", "v1", "attestation-cases.json"],
    (c) => c.decode === true && c.verify === true,
    "role attestation",
  );
  const ca1 = firstCase(
    ["priv", "conformance", "attestation-profiles", "content-assertion", "v1", "assertion-structure-cases.json"],
    (c) => c.id === "valid-genesis" && c.class === "valid" && c.expected.decode === "valid" && c.expected.verify === "valid",
    "content assertion",
  );
  out.push(
    { profile: PROFILE_LOOPBACK, label: "loopback-proof", compact: loopback.compact },
    { profile: PROFILE_RA1, label: "role-attestation", compact: ra1.compact },
    { profile: PROFILE_CA1, label: "content-assertion", compact: ca1.compact },
  );
  return out;
}

const edSig = (rBytes, s) => Buffer.concat([Buffer.from(rBytes), Ref.bigToLe(s, 32)]);

function familyEd25519Assemble() {
  const cases = [];
  for (const t of ed25519Templates()) {
    const { signature } = splitCompact(t.compact);
    const label = t.profile ? t.label : `v${t.major}-${t.kind.replaceAll("_", "-")}`;
    assertTemplate(label, "ed25519", signature);
    const r = signature.subarray(0, 32);
    const s = Ref.leToBig(signature.subarray(32));
    const variants = [
      ["s-equals-l", edSig(r, Ref.L), "invalid", "S = L"],
      ["s-l-minus-one", edSig(r, Ref.L - 1n), "valid", "S = L - 1, emitted unchanged"],
      ["r-small-order-identity", edSig(IDENTITY_R, s), "invalid", "R = 01 00..00 (the identity, order 1)"],
      ["r-noncanonical-y-p", edSig(NONCANONICAL_R, s), "invalid", "R = p little-endian (y = p, non-canonical)"],
    ];
    for (const [variant, sig, intent, signatureNote] of variants) {
      cases.push(
        assembleCase({
          id: `assemble-${label}-${variant}`,
          rule: t.profile ? PROFILE_RULES[t.profile] : RULE_ED25519[t.major],
          major: t.major,
          profile: t.profile,
          kind: t.kind,
          compact: t.compact,
          signature: sig,
          intent,
          construction: { signature: signatureNote, template: t.profile ? `certified ${t.profile}` : `certified v${t.major} ${t.kind}` },
        }),
      );
    }
  }
  return cases;
}

function familyEd25519Export() {
  const cases = [];
  for (const major of [1, 2]) {
    const template = exportTemplate(major);
    cases.push(
      exportCase({
        id: `encode-anchored-export-v${major}-start-anchor-s-equals-l`,
        rule: RULE_ED25519[major],
        major,
        template,
        position: "start_anchor",
        mutate: (signature) => edSig(signature.subarray(0, 32), Ref.L),
        suite: "ed25519",
        construction: { signature: "S = L on the certified start anchor signature", template: template.id },
      }),
      exportCase({
        id: `encode-anchored-export-v${major}-transition-r-small-order-identity`,
        rule: RULE_ED25519[major],
        major,
        template,
        position: "transition",
        mutate: (signature) => edSig(IDENTITY_R, Ref.leToBig(signature.subarray(32))),
        suite: "ed25519",
        construction: { signature: "R = 01 00..00 (the identity) on the certified transition signature", template: template.id },
      }),
    );
  }
  return cases;
}

// ---- file emission -----------------------------------------------------------------------------

function jsonStats(value, depth = 0) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "string" && Buffer.byteLength(value, "utf8") > LIMITS.string_bytes) fail("string_bytes bound");
    return { nodes: 1, depth };
  }
  let nodes = 1;
  let maxDepth = depth + 1;
  const entries = Array.isArray(value) ? value.map((v) => [null, v]) : Object.entries(value);
  if (Array.isArray(value) && value.length > LIMITS.array_items) fail("array_items bound");
  if (!Array.isArray(value) && entries.length > LIMITS.object_members) fail("object_members bound");
  for (const [k, v] of entries) {
    if (k !== null && Buffer.byteLength(k, "utf8") > LIMITS.key_bytes) fail("key_bytes bound");
    const s = jsonStats(v, depth + 1);
    nodes += s.nodes;
    maxDepth = Math.max(maxDepth, s.depth);
  }
  return { nodes, depth: maxDepth };
}

function caseFile(family, cases) {
  return {
    cases,
    family,
    format: FORMAT_CASES,
    provenance: { generator: GENERATOR_PATH, private_material_tracked: false, verdict_source: "rule-text-bigint" },
  };
}

// Greedy split so every file stays inside FILE_BUDGET; deterministic names.
function emit(files, family, stem, cases) {
  const chunks = [];
  let current = [];
  const fits = (list) => {
    const doc = caseFile(family, list);
    const bytes = Buffer.byteLength(canonical(doc), "utf8") + 1;
    const { nodes } = jsonStats(doc);
    return bytes <= FILE_BUDGET.bytes && nodes <= FILE_BUDGET.nodes && list.length <= FILE_BUDGET.cases;
  };
  for (const c of cases) {
    if (current.length > 0 && !fits([...current, c])) {
      chunks.push(current);
      current = [];
    }
    current.push(c);
    if (!fits(current)) fail(`${family}/${stem}: single case ${c.id} exceeds the file budget`);
  }
  if (current.length > 0) chunks.push(current);
  chunks.forEach((chunk, i) => {
    const name = chunks.length === 1 ? `${stem}.json` : `${stem}-${String(i + 1).padStart(2, "0")}.json`;
    files.push({ path: `cases/${family}/${name}`, family, cases: chunk.length, doc: caseFile(family, chunk) });
  });
}

const FAMILIES = ["ed25519-assemble", "ed25519-export-encode", "es256-assemble", "es256-export-encode"];

function profileDoc(ruleIds) {
  return {
    case_envelope: {
      common: "id, rule (the requirement id the case certifies), surface, class, input, expected, construction {signature, template}",
      major:
        "cases with `major` (1, 2 or 3) run that contract-major's surface (assemble_compact or encode_anchored_export) with exactly that major corpus's input and expected shapes",
      profile:
        "cases with `profile` run that sibling profile's assemble_compact; input {protected_segment, payload_segment, signature}, the signing-input kind implied by the profile",
    },
    class_mapping: "a refused signature is invalid_encoding; a signature exactly at the rule's bound (s = floor(n/2), S = L - 1) is exact_bound",
    families: FAMILIES,
    format: FORMAT_PROFILE,
    profile: PROFILE,
    requirement_ids: ruleIds,
    revision: REVISION,
    rule: [
      "ES256 (contract-major 3): every framed signature r || s has 0 < r < n and 0 < s <= floor(n/2), n the P-256 group order",
      "Ed25519 (contract-majors 1 and 2, local loopback, role attestation, content assertion): every framed signature R || S has R canonical (y < p, and no sign bit when x = 0), R not of small order, and S < L",
      "a producer surface returns exactly the closed error for a refused signature and emits every accepted signature's bytes unchanged; it holds no key and verifies no signature",
    ],
    valid_case_note:
      "the exact_bound cases pin the producer predicate's boundary only; their signatures are not verifiable signatures, and a verifier rejects them",
    verdict_source:
      "the rule text in pure BigInt arithmetic (no table, no backend); cross-checked at generation by byte-level comparisons and the literal small-order table",
  };
}

function buildCorpus() {
  const files = [];
  emit(files, "es256-assemble", "assemble", familyEs256Assemble());
  emit(files, "es256-export-encode", "encode", familyEs256Export());
  emit(files, "ed25519-assemble", "assemble", familyEd25519Assemble());
  emit(files, "ed25519-export-encode", "encode", familyEd25519Export());

  if (disagreements.length > 0) {
    fail(`cross-check FAILED: ${disagreements.length} disagreement(s):\n  ${disagreements.join("\n  ")}`);
  }

  const ids = new Set();
  const ruleIds = new Set();
  for (const f of files) {
    for (const c of f.doc.cases) {
      if (ids.has(c.id)) fail(`duplicate case id ${c.id}`);
      ids.add(c.id);
      ruleIds.add(c.rule);
    }
  }

  const out = new Map();
  const put = (path, doc) => {
    const bytes = Buffer.from(`${canonical(doc)}\n`, "utf8");
    if (bytes.length > LIMITS.json_bytes) fail(`${path}: json_bytes bound`);
    const { nodes, depth } = jsonStats(doc);
    if (nodes > LIMITS.total_nodes || depth > LIMITS.depth) fail(`${path}: total_nodes/depth bound (${nodes}/${depth})`);
    out.set(path, bytes);
  };
  put("profile.json", profileDoc([...ruleIds].sort()));
  put("revision.json", { format: FORMAT_REVISION, generated_from: GENERATOR_PATH, revision: REVISION });
  for (const f of files) put(f.path, f.doc);

  const families = {};
  for (const f of files) families[f.family] = (families[f.family] ?? 0) + f.cases;
  const indexFiles = [...out.entries()]
    .map(([path, bytes]) => ({ cases: files.find((f) => f.path === path)?.cases ?? 0, path, sha256: hex(sha256(bytes)) }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  put("index.json", {
    families,
    files: indexFiles,
    format: FORMAT_INDEX,
    private_material_tracked: false,
    profile: PROFILE,
    revision: REVISION,
    total_cases: indexFiles.reduce((acc, f) => acc + f.cases, 0),
  });
  const verdicts = { valid: 0, invalid: 0 };
  for (const f of files) for (const c of f.doc.cases) verdicts[c.expected.verdict] += 1;
  return { out, families, verdicts };
}

// ---- main --------------------------------------------------------------------------------------

function listTree(dir) {
  const found = [];
  if (!existsSync(dir)) return found;
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const full = join(current, name);
      if (statSync(full).isDirectory()) walk(full);
      else found.push(relative(dir, full).split(sep).join("/"));
    }
  };
  walk(dir);
  return found;
}

function main() {
  const { out, families, verdicts } = buildCorpus();
  const indexSha = hex(sha256(out.get("index.json")));
  if (ARGS.mode === "verify") {
    const shipped = listTree(ARGS.out);
    const problems = [];
    for (const path of shipped) if (!out.has(path)) problems.push(`unexpected file ${path}`);
    for (const [path, bytes] of out) {
      const full = join(ARGS.out, path);
      if (!existsSync(full)) problems.push(`missing file ${path}`);
      else if (!readFileSync(full).equals(bytes)) problems.push(`drifted file ${path}`);
    }
    if (problems.length > 0) fail(`verify FAILED:\n  ${problems.join("\n  ")}`);
  } else {
    for (const path of listTree(ARGS.out)) if (!out.has(path) && path.endsWith(".json")) rmSync(join(ARGS.out, path));
    for (const [path, bytes] of out) {
      mkdirSync(dirname(join(ARGS.out, path)), { recursive: true });
      writeFileSync(join(ARGS.out, path), bytes);
    }
  }
  const total = Object.values(families).reduce((a, b) => a + b, 0);
  console.log(`build_producer_canonicality: ${ARGS.mode === "verify" ? "verify ok" : "wrote"} ${ARGS.out}`);
  console.log(`  node ${process.version}; files=${out.size}; total_cases=${total}; valid=${verdicts.valid} invalid=${verdicts.invalid}; index sha256=${indexSha}`);
  console.log(`  families ${JSON.stringify(families)}`);
  console.log(
    `  cross-check: signatures=${stats.checked} templates=${stats.templates} high-s-node-verified=${stats.highSNodeVerified} disagreements=${disagreements.length}`,
  );
}

main();
