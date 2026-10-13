#!/usr/bin/env node
// Strict-Ed25519 corpus generator (authoring tooling; NOT a conformance runner; not in the Hex
// package, whose `files` list does not include conformance/).
//
// Writes the additive corpus priv/conformance/strict-ed25519/ (profile `bap-strict-ed25519/1`):
// profile.json, revision.json, cases/<family>/*.json and index.json. No existing corpus file is
// read for anything but TEMPLATES (header/payload/input shapes of one valid case per surface), and
// none is written.
//
// Expected verdicts. Every verdict comes from pure BigInt arithmetic in
// strict_ed25519_reference.mjs: the strict RFC 8032 section 5.1.3 decode (canonical = y < p and no
// sign bit when x = 0), the order test [8]P == O for small order, S < L, and the cofactorless
// equation encode([S]B - [k]A) == R compared byte for byte. There is no small-order blocklist, no
// canonical-encoding byte table and no Ed25519 backend in the verdict path.
//
// Cross-check (fails generation on any disagreement). Every signature verdict is recomputed
// independently by the S1 gate as the design writes it (the byte-level canonical test, the
// literal 8-entry small-order table, S < L) in front of node:crypto verify; every key-acceptance
// verdict by the same byte gate plus an Euler-criterion on-curve test; every torsion-freedom
// verdict against the key's construction provenance. Forged vectors must also be ACCEPTED by an
// ungated lenient cofactorless equation (proof that each forgery is real, not trivially invalid);
// the cofactored-only vector must be accepted by the cofactored equation. Every honest test key is
// checked against node:crypto (public key derivation and an RFC 8032 signature, byte for byte).
//
// Determinism. Output is byte-identical on every run: canonical JSON, fixed iteration order, and
// every random choice drawn from a SHA-512 counter DRBG over a fixed label (DRBG_DOMAIN below).
//
// Test seeds (documented here, never written into the corpus). Honest test keys are derived as
//   seed = SHA-256(UTF-8("bap-strict-ed25519/1 test seed " || name))
// for the names used in this file (issuer, holder, archive-a, archive-b, attestor, subject,
// loopback-issuer, signer, and the derived `<position>/...` and `differential-<n>` names). Like the
// RFC 8032 section 7.1 test keys these are PUBLIC test keys: their private halves are derivable
// from this source by design, so they authorize nothing. The corpus files carry public keys,
// signatures and messages only (`private_material_tracked: false`); no seed, scalar or private JWK
// member is ever written. The existing corpora were minted with ephemeral, destroyed keys; this
// corpus instead requires byte-identical regeneration, which ephemeral keys cannot give.
//
// Taming the many EdDSAs (Chalkias, Garillot, Nikolaenko, SSR 2020; IACR ePrint 2020/1244). The
// 12 vectors are imported byte for byte from github.com/novifinancial/ed25519-speccheck, commit
// 65519336fda78a3d016e947df6d82848aca0c9da, file cases.json (git blob
// 8686dcb7eef8b6abe36ca8fa9bb10de112e63774, 3589 bytes, SHA-256
// 08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450), licensed Apache-2.0
// (repository LICENSE and README "License" section). The text is embedded verbatim below and its
// SHA-256 is asserted at every run.
//
// Usage:
//   node conformance/generators/build_strict_ed25519.mjs            # (re)write the corpus
//   node conformance/generators/build_strict_ed25519.mjs --verify   # shipped corpus == rebuild
//   ... [--out DIR] [--repo-root DIR]                                # alternate output / templates

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import * as Ref from "./strict_ed25519_reference.mjs";

const PROFILE = "bap-strict-ed25519/1";
const REVISION = 1;
const REVISION_NOTE = "conformance/generators/build_strict_ed25519.mjs";
const FORMAT_CASES = "bounded-authority-protocol-strict-ed25519-conformance-cases";
const FORMAT_INDEX = "bounded-authority-protocol-strict-ed25519-conformance-corpus-index";
const FORMAT_REVISION = "bounded-authority-protocol-strict-ed25519-conformance-corpus-revision";
const GENERATOR_PATH = "conformance/generators/build_strict_ed25519.mjs";
const SEED_DOMAIN = "bap-strict-ed25519/1 test seed ";
const DRBG_DOMAIN = "bap-strict-ed25519/1 drbg ";
const TORSION_NOTE = "accepted at verify; rejected by torsion_free?";

// Every case file must load through the reference JSON decoder at Bounds.maximum() (the corpus
// loaders decode whole files under the protocol maxima). Files are split to stay inside a margin.
const LIMITS = { json_bytes: 65536, total_nodes: 4096, depth: 32, object_members: 64, array_items: 256, string_bytes: 8192, key_bytes: 128 };
const FILE_BUDGET = { bytes: 60000, nodes: 3600, cases: 256 };

// ---- arguments ------------------------------------------------------------------------------

function fail(message) {
  console.error(`build_strict_ed25519: ${message}`);
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
  if (!args.out) args.out = join(args.repoRoot, "priv", "conformance", "strict-ed25519");
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
const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
};
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (text) => Buffer.from(text, "hex");

function thumbprint(publicKey) {
  return b64u(sha256(Buffer.from(canonical({ crv: "Ed25519", kty: "OKP", x: b64u(publicKey) }), "utf8")));
}

function jwkText(publicKey) {
  return canonical({ crv: "Ed25519", kty: "OKP", x: b64u(publicKey) });
}

// The typed projection of the request digest (spec bap-v1.md "request digest"): JCS of
// [operation, typed(cast_arguments)] behind the major's prefix.
function typed(value) {
  if (value === null) return ["null"];
  if (typeof value === "boolean") return ["boolean", value];
  if (typeof value === "string") return ["string", value];
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("typed: only safe integers are authored");
    return ["integer", value];
  }
  if (Array.isArray(value)) return ["array", value.map(typed)];
  const obj = Object.create(null);
  for (const [k, v] of Object.entries(value)) obj[k] = typed(v);
  return ["object", obj];
}

function requestDigest(major, operation, castArguments) {
  const prefix = Buffer.from(`BAP${major}-REQUEST\0`, "binary");
  return b64u(sha256(prefix, Buffer.from(canonical([operation, typed(castArguments)]), "utf8")));
}

// ---- deterministic randomness and test keys -------------------------------------------------

function drbg(label) {
  let counter = 0;
  const next = () => createHash("sha512").update(`${DRBG_DOMAIN}${label}/${counter++}`, "utf8").digest();
  return {
    scalar() {
      for (;;) {
        const v = Ref.leToBig(next()) % Ref.L;
        if (v !== 0n) return v;
      }
    },
    pick(n) {
      return Number(Ref.leToBig(next()) % BigInt(n));
    },
  };
}

const PKCS8_ED25519_PREFIX = fromHex("302e020100300506032b657004220420");
const SPKI_ED25519_PREFIX = fromHex("302a300506032b6570032100");
const SELF_CHECK_MESSAGE = Buffer.from("bap-strict-ed25519/1 key self-check", "utf8");

const keyCache = new Map();

function honestKey(name) {
  if (keyCache.has(name)) return keyCache.get(name);
  const seed = sha256(Buffer.from(SEED_DOMAIN + name, "utf8"));
  const { scalar, prefix } = Ref.expandSeed(seed);
  const publicKey = Ref.encodePoint(Ref.multiply(scalar, Ref.BASE));
  // Cross-check the arithmetic against node:crypto: key derivation and one deterministic signature.
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
  const nodePublic = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(SPKI_ED25519_PREFIX.length);
  if (!nodePublic.equals(publicKey)) fail(`key ${name}: BigInt public key != node:crypto public key`);
  const nodeSignature = nodeSign(null, SELF_CHECK_MESSAGE, privateKey);
  if (!nodeSignature.equals(Ref.signHonest(seed, SELF_CHECK_MESSAGE, publicKey))) {
    fail(`key ${name}: BigInt signature != node:crypto signature`);
  }
  stats.honestKeysChecked += 1;
  const key = { label: `honest:${name}`, name, seed, scalar, prefix, publicKey, torsion: 0 };
  keyCache.set(name, key);
  return key;
}

// Every mixed-order key a vector accepts at verify ("accepted at verify; rejected by
// torsion_free?") is registered here so the key-acceptance family carries its second leg.
const notedKeys = new Map();
function noteKey(key) {
  notedKeys.set(key.label, key.publicKey);
  return key;
}

// A + T_i for an honest A = [a]B: mixed order for i != 0. The key holder knows a.
function mixedKey(name, torsionIndex) {
  const base = honestKey(name);
  const point = Ref.add(Ref.multiply(base.scalar, Ref.BASE), T[torsionIndex]);
  return { ...base, label: `torsion-variant:${name}+T${torsionIndex}`, publicKey: Ref.encodePoint(point), torsion: torsionIndex };
}

// ---- derived point sets (arithmetic, no tables) ----------------------------------------------

const stats = {
  honestKeysChecked: 0,
  signaturesChecked: 0,
  gatePassing: 0,
  nodeVerifyCalls: 0,
  ungatedNodeAcceptsRejected: 0,
  keysChecked: 0,
  torsionChecked: 0,
};
const disagreements = [];

const T = Ref.torsionPoints();
const SMALL_ORDER = T.map((point, index) => ({
  label: `small-order-${index}`,
  index,
  order: Ref.pointOrder(point),
  bytes: Ref.encodePoint(point),
}));

function enumerateNoncanonical() {
  const out = [];
  for (let t = 0n; t < 19n; t += 1n) {
    for (const sign of [0n, 1n]) {
      out.push({ label: `y-p-plus-${t}${sign ? "-sign" : ""}`, bytes: Ref.bigToLe((Ref.P + t) | (sign << 255n), 32) });
    }
  }
  out.push({ label: "x0-sign-identity", bytes: Ref.bigToLe(1n | (1n << 255n), 32) });
  out.push({ label: "x0-sign-order2", bytes: Ref.bigToLe((Ref.P - 1n) | (1n << 255n), 32) });
  for (const entry of out) {
    const c = Ref.classifyEncoding(entry.bytes);
    if (c.kind !== "noncanonical") fail(`enumeration: ${entry.label} is not non-canonical`);
    entry.decodes = c.point === null ? "off-curve" : Ref.isSmallOrder(c.point) ? "small-order" : "mixed-order";
  }
  return out;
}

const NONCANONICAL = enumerateNoncanonical();
const NONCANONICAL_SMALL = NONCANONICAL.filter((e) => e.decodes === "small-order");
{
  const census = { "small-order": 0, "mixed-order": 0, "off-curve": 0 };
  for (const e of NONCANONICAL) census[e.decodes] += 1;
  // Sanity against the design's census (1.6): 6 small-order, 20 mixed-order, 14 off-curve.
  if (census["small-order"] !== 6 || census["mixed-order"] !== 20 || census["off-curve"] !== 14) {
    fail(`non-canonical census ${JSON.stringify(census)}`);
  }
}

function offCurveCanonical(count) {
  const out = [];
  for (let y = 2n; out.length < count; y += 1n) {
    const bytes = Ref.bigToLe(y, 32);
    if (Ref.classifyEncoding(bytes).kind === "offcurve") out.push({ label: `offcurve-y-${y}`, bytes });
  }
  return out;
}

const OFF_CURVE = offCurveCanonical(2);
const IDENTITY_BYTES = Ref.encodePoint(Ref.IDENTITY);
const ALIAS_IDENTITY_Y1P = NONCANONICAL.find((e) => e.label === "y-p-plus-1").bytes;
const ALIAS_IDENTITY_X0 = NONCANONICAL.find((e) => e.label === "x0-sign-identity").bytes;

// ---- the cross-check: S1 gate (as the design writes it) + node:crypto -------------------------

// The design's literal small-order table (3.1). It is used ONLY here, as the thing under
// cross-check: a typo in it disagrees with the [8]P == O arithmetic and fails generation.
const GATE_SMALL_ORDER_TABLE = new Set([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]);
const GATE_X0_SIGN = new Set([
  "0100000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]);

function gateCanonical(bytes) {
  let yAtLeastP = (bytes[31] & 0x7f) === 0x7f && bytes[0] >= 0xed;
  for (let i = 1; i <= 30 && yAtLeastP; i += 1) if (bytes[i] !== 0xff) yAtLeastP = false;
  return !yAtLeastP && !GATE_X0_SIGN.has(hex(bytes));
}

function nodeEd25519Verify(publicKey, signature, message) {
  stats.nodeVerifyCalls += 1;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]), format: "der", type: "spki" });
    return nodeVerify(null, message, key, signature);
  } catch {
    return false;
  }
}

function gateVerify(publicKey, signature, message) {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const r = signature.subarray(0, 32);
  if (!gateCanonical(publicKey) || !gateCanonical(r)) return false;
  if (GATE_SMALL_ORDER_TABLE.has(hex(publicKey)) || GATE_SMALL_ORDER_TABLE.has(hex(r))) return false;
  if (Ref.leToBig(signature.subarray(32)) >= Ref.L) return false;
  stats.gatePassing += 1;
  return nodeEd25519Verify(publicKey, signature, message);
}

// On-curve by Euler's criterion on x^2 = (y^2 - 1) / (d y^2 + 1): a different computation from
// the reference's square-root decode.
function eulerOnCurve(bytes) {
  const y = Ref.leToBig(bytes) & ((1n << 255n) - 1n);
  if (y >= Ref.P) return false;
  const u = (((y * y - 1n) % Ref.P) + Ref.P) % Ref.P;
  const v = (Ref.D * y * y + 1n) % Ref.P;
  const x2 = (u * Ref.powmod(v, Ref.P - 2n)) % Ref.P;
  return x2 === 0n || Ref.powmod(x2, (Ref.P - 1n) / 2n) === 1n;
}

function gateKeyAcceptable(bytes) {
  if (bytes.length !== 32) return false;
  return gateCanonical(bytes) && !GATE_SMALL_ORDER_TABLE.has(hex(bytes)) && eulerOnCurve(bytes);
}

const signatureMemo = new Map();

function signatureVerdict(publicKey, signature, message, context) {
  const memoKey = `${hex(publicKey)}|${hex(signature)}|${hex(message)}`;
  if (signatureMemo.has(memoKey)) return signatureMemo.get(memoKey);
  const reference = Ref.verifyStrict(publicKey, signature, message);
  const gated = gateVerify(publicKey, signature, message);
  stats.signaturesChecked += 1;
  if (reference.valid !== gated) {
    disagreements.push(`${context}: reference=${reference.valid} (${reference.reason}) gate+node=${gated}`);
  }
  if (!reference.valid && publicKey.length === 32 && signature.length === 64 && nodeEd25519Verify(publicKey, signature, message)) {
    stats.ungatedNodeAcceptsRejected += 1;
  }
  signatureMemo.set(memoKey, reference);
  return reference;
}

function keyVerdict(publicKey, context) {
  const reference = Ref.acceptablePublicKey(publicKey);
  stats.keysChecked += 1;
  if (reference.valid !== gateKeyAcceptable(publicKey)) {
    disagreements.push(`${context}: acceptable reference=${reference.valid} (${reference.reason}) gate=${!reference.valid}`);
  }
  return reference;
}

function torsionVerdict(publicKey, expectedByConstruction, context) {
  const reference = Ref.torsionFree(publicKey);
  stats.torsionChecked += 1;
  if (reference.valid !== expectedByConstruction) {
    disagreements.push(`${context}: torsion_free reference=${reference.valid} (${reference.reason}) construction=${expectedByConstruction}`);
  }
  return reference;
}

function verifyCofactored(publicKey, signature, message) {
  const a = Ref.lenientDecode(publicKey);
  const r = Ref.lenientDecode(signature.subarray(0, 32));
  const s = Ref.leToBig(signature.subarray(32));
  if (a === null || r === null || s >= Ref.L) return false;
  const k = Ref.challenge(signature.subarray(0, 32), publicKey, message);
  const lhs = Ref.add(Ref.add(Ref.multiply(s, Ref.BASE), Ref.negate(r)), Ref.negate(Ref.multiply(k, a)));
  return Ref.isIdentity(Ref.multiply(8n, lhs));
}

// ---- rule ids (design 4.3 item 6) ------------------------------------------------------------

const REASON_RULE = {
  "a-noncanonical": "SIGNING-ed25519-canonical-point",
  "r-noncanonical": "SIGNING-ed25519-canonical-point",
  "a-small-order": "SIGNING-ed25519-small-order-reject",
  "r-small-order": "SIGNING-ed25519-small-order-reject",
  "s-range": "SIGNING-ed25519-scalar-range",
  equation: "SIGNING-ed25519-cofactorless",
  valid: "SIGNING-ed25519-cofactorless",
  "a-off-curve": "SIGNING-backend-reject",
  width: "SIGNING-backend-reject",
};
const signingRule = (major, reason) => `REQ${major}-${REASON_RULE[reason ?? "valid"]}`;
const keyRule = (major) => `REQ${major}-KEY-ed25519-acceptable`;
const torsionRule = (major) => `REQ${major}-HOST-ed25519-torsion-free`;
// The JSON algebra is shared by both majors; the requirement map defines the JCS rule once.
const jcsRule = () => "REQ1-JSON-jcs-exact";

// ---- signers ---------------------------------------------------------------------------------
// A signer is { publicKey, keyLabel, sigLabel, forgery, cofactoredOnly, sign(message) -> Buffer|null }.
// null means "this construction does not exist for this message"; the scenario then retries with
// its next candidate.

const S_BYTES = (s) => Ref.bigToLe(s, 32);

function honestSigner(key) {
  return { publicKey: key.publicKey, keyLabel: key.label, sigLabel: "honest", sign: (m) => Ref.signHonest(key.seed, m, key.publicKey) };
}

// No private key: A small-order (canonical or alias), R = identity-class small point, S = 0.
function forgedZeroSigner(aBytes, keyLabel) {
  return {
    publicKey: aBytes,
    keyLabel,
    sigLabel: "forged-small-r-s0",
    forgery: true,
    sign(message) {
      for (const point of T) {
        const sig = Buffer.concat([Ref.encodePoint(point), S_BYTES(0n)]);
        if (Ref.verifyUngatedCofactorless(aBytes, sig, message)) return sig;
      }
      return null;
    },
  };
}

// No private key: A small-order (canonical or alias), R = [S]B + T_j (never small order), S != 0.
// Isolates the A rule: R is canonical, prime-order-or-mixed, S < L.
function forgedIsolatedSigner(aBytes, keyLabel, rngLabel) {
  return {
    publicKey: aBytes,
    keyLabel,
    sigLabel: "forged-isolated",
    forgery: true,
    sign(message) {
      const rng = drbg(`${rngLabel}/${hex(sha256(message))}`);
      for (let attempt = 0; attempt < 256; attempt += 1) {
        const s = rng.scalar();
        const sb = Ref.multiply(s, Ref.BASE);
        for (const point of T) {
          const sig = Buffer.concat([Ref.encodePoint(Ref.add(sb, point)), S_BYTES(s)]);
          if (Ref.verifyUngatedCofactorless(aBytes, sig, message)) return sig;
        }
      }
      return null;
    },
  };
}

// Key holder: R = rBytes chosen, S = k * a. Valid under the ungated equation iff
// [S]B - [k]A encodes to rBytes.
function keyHolderFixedRSigner(key, rBytes, sigLabel, { requireUngated }) {
  return {
    publicKey: key.publicKey,
    keyLabel: key.label,
    sigLabel,
    forgery: requireUngated,
    sign(message) {
      const k = Ref.challenge(rBytes, key.publicKey, message);
      const sig = Buffer.concat([rBytes, S_BYTES((k * key.scalar) % Ref.L)]);
      if (requireUngated && !Ref.verifyUngatedCofactorless(key.publicKey, sig, message)) return null;
      return sig;
    },
  };
}

function scalarPlusLSigner(key, mode) {
  return {
    publicKey: key.publicKey,
    keyLabel: key.label,
    sigLabel: mode,
    sign(message) {
      const sig = Ref.signHonest(key.seed, message, key.publicKey);
      const s = Ref.leToBig(sig.subarray(32));
      const n = mode === "s-plus-l" ? 1n : ((1n << 256n) - 1n - s) / Ref.L;
      return Buffer.concat([sig.subarray(0, 32), S_BYTES(s + n * Ref.L)]);
    },
  };
}

function nonceScalar(key, message, label) {
  return Ref.leToBig(Ref.sha512(key.prefix, Buffer.from(label, "utf8"), message)) % Ref.L;
}

// Key holder: honest A, R = [r]B + T1 (mixed), S = r + k a: passes the cofactored equation only.
function mixedRSigner(key) {
  return {
    publicKey: key.publicKey,
    keyLabel: key.label,
    sigLabel: "key-holder-mixed-r",
    cofactoredOnly: true,
    sign(message) {
      const r = nonceScalar(key, message, "mixed-r");
      const rBytes = Ref.encodePoint(Ref.add(Ref.multiply(r, Ref.BASE), T[1]));
      const k = Ref.challenge(rBytes, key.publicKey, message);
      return Buffer.concat([rBytes, S_BYTES((r + k * key.scalar) % Ref.L)]);
    },
  };
}

// Key holder of a mixed-order A = [a]B + T: R = [r]B + T_j with T_j = -[k]T, S = r + k a. Passes
// the cofactorless AND the cofactored equation; S1 accepts it at verify.
function mixedBothSigner(key) {
  return {
    publicKey: key.publicKey,
    keyLabel: key.label,
    sigLabel: "key-holder-mixed-a-mixed-r",
    sign(message) {
      for (let attempt = 0; attempt < 256; attempt += 1) {
        const r = nonceScalar(key, message, `mixed-both/${attempt}`);
        const rb = Ref.multiply(r, Ref.BASE);
        for (const point of T) {
          const rBytes = Ref.encodePoint(Ref.add(rb, point));
          const k = Ref.challenge(rBytes, key.publicKey, message);
          const sig = Buffer.concat([rBytes, S_BYTES((r + k * key.scalar) % Ref.L)]);
          if (Ref.verifyUngatedCofactorless(key.publicKey, sig, message)) return sig;
        }
      }
      return null;
    },
  };
}

// ---- scenarios -------------------------------------------------------------------------------
// A scenario is { id, intent, expectValid, note?, candidate(attempt) -> signer }.
// `intent` is the rule the vector isolates; the generator asserts the arithmetic agrees.

function signerScenarios(position, honestName) {
  const honest = () => honestKey(honestName);
  const list = [];
  list.push({ id: "forged-identity-rs0", intent: "a-small-order", candidate: () => forgedZeroSigner(IDENTITY_BYTES, "small-order-0") });
  for (const so of SMALL_ORDER) {
    list.push({
      id: `iso-small-order-a-${so.index}`,
      intent: "a-small-order",
      candidate: () => forgedIsolatedSigner(so.bytes, so.label, `${position}/iso-a/${so.index}`),
    });
  }
  for (const nc of NONCANONICAL_SMALL) {
    list.push({
      id: `iso-noncanonical-a-${nc.label}`,
      intent: "a-noncanonical",
      candidate: () => forgedIsolatedSigner(nc.bytes, nc.label, `${position}/iso-nc/${nc.label}`),
    });
  }
  list.push({
    id: "honest-a-identity-r",
    intent: "r-small-order",
    candidate: () => keyHolderFixedRSigner(honest(), IDENTITY_BYTES, "key-holder-identity-r", { requireUngated: true }),
  });
  for (let j = 0; j < 8; j += 1) {
    list.push({
      id: `mixed-a-small-r-${j}`,
      intent: "r-small-order",
      maxAttempts: 2048,
      candidate: (attempt) =>
        keyHolderFixedRSigner(
          mixedKey(`${position}/mixed-a-small-r-${j}/${Math.floor(attempt / 7)}`, 1 + (attempt % 7)),
          SMALL_ORDER[j].bytes,
          `key-holder-small-r-${j}`,
          { requireUngated: true },
        ),
    });
  }
  for (const [label, alias] of [["y-p-plus-1", ALIAS_IDENTITY_Y1P], ["x0-sign-identity", ALIAS_IDENTITY_X0]]) {
    list.push({
      id: `honest-a-noncanonical-r-${label}`,
      intent: "r-noncanonical",
      candidate: () => keyHolderFixedRSigner(honest(), alias, `key-holder-noncanonical-r-${label}`, { requireUngated: false }),
    });
  }
  list.push({ id: "s-plus-l", intent: "s-range", candidate: () => scalarPlusLSigner(honest(), "s-plus-l") });
  list.push({ id: "s-plus-max-l", intent: "s-range", candidate: () => scalarPlusLSigner(honest(), "s-plus-max-l") });
  list.push({ id: "honest-a-mixed-r", intent: "equation", candidate: () => mixedRSigner(honest()) });
  list.push({
    id: "mixed-a-mixed-r-both",
    intent: "valid",
    note: TORSION_NOTE,
    candidate: (attempt) => mixedBothSigner(noteKey(mixedKey(`${position}/mixed-a-mixed-r-both/${attempt}`, 1))),
  });
  return list;
}

// Data positions: the key is only carried (fingerprinted, attested, chained), never a signer.
function dataKeyScenarios(position) {
  const list = [];
  for (const so of SMALL_ORDER) list.push({ id: `small-order-key-${so.index}`, key: so.bytes, keyLabel: so.label, torsionFree: false });
  for (const nc of NONCANONICAL) list.push({ id: `noncanonical-key-${nc.label}`, key: nc.bytes, keyLabel: `${nc.label} (${nc.decodes})`, torsionFree: false });
  for (const oc of OFF_CURVE) list.push({ id: `offcurve-key-${oc.label}`, key: oc.bytes, keyLabel: oc.label, torsionFree: false });
  const variant = noteKey(mixedKey(`${position}/torsion-variant`, 1));
  list.push({ id: "torsion-variant-key", key: variant.publicKey, keyLabel: variant.label, torsionFree: false, note: TORSION_NOTE });
  return list;
}

// ---- artifact assembly -----------------------------------------------------------------------

function readJson(rel) {
  return JSON.parse(readFileSync(join(REPO, rel), "utf8"));
}

function templateCase(rel, id) {
  const file = readJson(rel);
  const list = Array.isArray(file) ? file : file.cases;
  const found = list.find((c) => c.id === id);
  if (!found) fail(`template ${rel}#${id} missing`);
  return structuredClone(found);
}

function splitCompact(compact, context) {
  const [h, p] = compact.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  // Re-encoding is byte-faithful only if the template segments are canonical: assert it.
  if (b64u(Buffer.from(canonical(header), "utf8")) !== h || b64u(Buffer.from(canonical(payload), "utf8")) !== p) {
    fail(`template ${context}: segments are not canonical JSON`);
  }
  return { header, payload };
}

class Retry extends Error {}

// Builds one JWS; records the signature for the verdict. Throws Retry when the signer has no
// construction for this message.
function signJws(record, role, header, payload, signer) {
  const h = b64u(Buffer.from(canonical(header), "utf8"));
  const p = b64u(Buffer.from(canonical(payload), "utf8"));
  const message = Buffer.from(`${h}.${p}`, "ascii");
  const signature = signer.sign(message);
  if (signature === null) throw new Retry();
  record.signatures.push({ role, signer, publicKey: signer.publicKey, signature, message });
  return `${h}.${p}.${b64u(signature)}`;
}

function newRecord() {
  return { signatures: [], keys: [] };
}

// Evaluates a record: every carried key through acceptable_public_key?, every signature through
// verify_strict, all cross-checked. Returns { valid, rule, reason }.
// Attribution: a failing signature names the signing rule its first failing clause belongs to (a
// signer's own weak key fails verify_strict on the A clauses); otherwise a failing carried key
// names the key-acceptance rule.
function evaluate(record, major, context) {
  let keyFailure = null;
  for (const { role, publicKey } of record.keys) {
    const v = keyVerdict(publicKey, `${context} key ${role}`);
    if (!v.valid && keyFailure === null) keyFailure = { rule: keyRule(major), reason: v.reason, kind: "key", role };
  }
  let signatureFailure = null;
  for (const s of record.signatures) {
    const v = signatureVerdict(s.publicKey, s.signature, s.message, `${context} sig ${s.role}`);
    if (s.signer.forgery && !Ref.verifyUngatedCofactorless(s.publicKey, s.signature, s.message)) {
      fail(`${context}: forged ${s.role} signature is not accepted by the ungated equation`);
    }
    if (s.signer.cofactoredOnly && !(verifyCofactored(s.publicKey, s.signature, s.message) && !Ref.verifyUngatedCofactorless(s.publicKey, s.signature, s.message))) {
      fail(`${context}: ${s.role} signature is not cofactored-only`);
    }
    if (!v.valid && signatureFailure === null) signatureFailure = { rule: signingRule(major, v.reason), reason: v.reason, kind: "signature", role: s.role };
  }
  if (signatureFailure !== null) return { valid: false, ...signatureFailure };
  if (keyFailure !== null) return { valid: false, ...keyFailure };
  return { valid: true, rule: signingRule(major, "valid"), reason: "valid" };
}

// A carried (non-signing) key: the vector isolates key acceptance, valid or not.
function evaluateCarried(record, major, context, expectValid) {
  const verdict = evaluate(record, major, context);
  if (verdict.valid !== expectValid || (!verdict.valid && verdict.rule !== keyRule(major))) {
    fail(`${context}: unexpected ${JSON.stringify(verdict)}`);
  }
  return { ...verdict, rule: keyRule(major) };
}

function runScenario(scenario, build, context) {
  const max = scenario.maxAttempts ?? 256;
  for (let attempt = 0; attempt < max; attempt += 1) {
    const signer = scenario.candidate(attempt);
    try {
      return { signer, ...build(signer) };
    } catch (error) {
      if (!(error instanceof Retry)) throw error;
    }
  }
  fail(`${context}: no construction found for ${scenario.id}`);
}

function checkIntent(scenario, result, major, context) {
  const expectedRule = signingRule(major, scenario.intent);
  if (result.verdict.rule !== expectedRule || result.verdict.valid !== (scenario.intent === "valid")) {
    fail(`${context}: ${scenario.id} intends ${expectedRule} but arithmetic gives ${result.verdict.rule} valid=${result.verdict.valid} (${result.verdict.reason})`);
  }
}

function v1Class(verdict) {
  if (verdict.valid) return "valid";
  return verdict.reason.startsWith("a-") || verdict.kind === "key" ? "invalid_key" : "invalid_encoding";
}

function v1Case({ id, family, major, surface, input, verdict, validExpected, construction, note, caseClass }) {
  const c = {
    id,
    rule: verdict.rule,
    major,
    surface,
    class: caseClass ?? v1Class(verdict),
    input,
    expected: verdict.valid ? { ...validExpected, verdict: "valid" } : { verdict: "invalid" },
    construction,
  };
  if (note) c.note = note;
  family.push(c);
}

function construction(position, keyLabel, sigLabel) {
  return { key: keyLabel, position, signature: sigLabel };
}

// ---- e2e: grant-verify -----------------------------------------------------------------------

const TEMPLATES = {
  grant: { 1: ["priv/conformance/v1/corpus/cases/grant-verify/verify.json", "verify-grant-valid"], 2: ["priv/conformance/v2/corpus/cases/grant-verify/verify.json", "verify-grant-v2-valid"] },
  envelope: { 1: ["priv/conformance/v1/corpus/cases/envelope/check.json", "check-envelope-valid"], 2: ["priv/conformance/v2/corpus/cases/envelope/check.json", "check-envelope-v2-valid"] },
  anchor: { 1: ["priv/conformance/v1/corpus/cases/boundary-anchor/verify.json", "verify-historical-anchor-valid"], 2: ["priv/conformance/v2/corpus/cases/boundary-anchor/verify.json", "verify-historical-anchor-v2-valid"] },
  transition: { 1: ["priv/conformance/v1/corpus/cases/key-transition/verify.json", "verify-key-transition-valid"], 2: ["priv/conformance/v2/corpus/cases/key-transition/verify.json", "verify-key-transition-v2-valid"] },
  export: { 1: ["priv/conformance/v1/corpus/cases/anchored-export/verify.json", "verify-anchored-export-valid"], 2: ["priv/conformance/v2/corpus/cases/anchored-export/verify.json", "verify-anchored-export-v2-valid"] },
};

function grantBuilder(major) {
  const t = templateCase(...TEMPLATES.grant[major]);
  const { header, payload } = splitCompact(t.input.compact, `grant v${major}`);
  return (issuer) => {
    const record = newRecord();
    record.keys.push({ role: "issuer", publicKey: issuer.publicKey });
    const compact = signJws(record, "issuer", header, payload, issuer);
    const input = { ...t.input, compact, public_key: b64u(issuer.publicKey) };
    const { verdict: _drop, ...validExpected } = t.expected;
    return { record, input, validExpected };
  };
}

function familyGrant(major) {
  const cases = [];
  const build = grantBuilder(major);
  const position = `grant-v${major}-issuer`;
  const baseline = { id: "honest", intent: "valid", candidate: () => honestSigner(honestKey("issuer")) };
  for (const scenario of [baseline, ...signerScenarios(position, "issuer")]) {
    const ctx = `grant-verify v${major} issuer ${scenario.id}`;
    const r = runScenario(scenario, build, ctx);
    r.verdict = evaluate(r.record, major, ctx);
    checkIntent(scenario, r, major, ctx);
    v1Case({
      id: `grant-verify-v${major}-issuer-${scenario.id}`,
      family: cases,
      major,
      surface: "verify_grant",
      input: r.input,
      verdict: r.verdict,
      validExpected: r.validExpected,
      construction: construction("issuer", r.signer.keyLabel, r.signer.sigLabel),
      note: scenario.note,
    });
  }
  for (const c of bomGrantCases(major)) cases.push(c);
  return cases;
}

// ---- BOM parity (independent review finding F1) -------------------------------------------------
// A leading U+FEFF inside a JSON string value or member name is ordinary string content: no
// conforming decoder strips it (REQ1-JSON-no-normalization). These grants are honestly signed (the
// generator asserts the Ed25519 layer accepts them), so their only defect is the BOM-prefixed
// value or name; a decoder that strips a leading U+FEFF would accept them.

const BOM = "\uFEFF";
const NO_NORMALIZATION_RULE = "REQ1-JSON-no-normalization";

const BOM_GRANT_VARIANTS = [
  ["header-alg", (h) => ({ ...h, alg: BOM + h.alg }), (p) => p, "invalid_algorithm"],
  ["header-typ", (h) => ({ ...h, typ: BOM + h.typ }), (p) => p, "invalid_claim"],
  ["header-kid", (h) => ({ ...h, kid: BOM + h.kid }), (p) => p, "invalid_claim"],
  ["payload-iss", (h) => h, (p) => ({ ...p, iss: BOM + p.iss }), "invalid_claim"],
  ["payload-jti", (h) => h, (p) => ({ ...p, jti: BOM + p.jti }), "invalid_claim"],
  [
    "payload-operation-name",
    (h) => h,
    (p) => ({ ...p, operations: [{ ...p.operations[0], name: BOM + p.operations[0].name }, ...p.operations.slice(1)] }),
    "invalid_claim",
  ],
  [
    "member-name-v",
    (h) => h,
    (p) => {
      const { v, ...rest } = p;
      return { ...rest, [BOM + "v"]: v };
    },
    "invalid_claim",
  ],
];

function bomGrantCases(major) {
  const t = templateCase(...TEMPLATES.grant[major]);
  const { header, payload } = splitCompact(t.input.compact, `grant v${major}`);
  const issuer = honestSigner(honestKey("issuer"));
  return BOM_GRANT_VARIANTS.map(([label, mapHeader, mapPayload, caseClass]) => {
    const ctx = `grant-verify v${major} bom ${label}`;
    const record = newRecord();
    record.keys.push({ role: "issuer", publicKey: issuer.publicKey });
    const h = mapHeader(header);
    const p = mapPayload(payload);
    if (!(canonical(h) + canonical(p)).includes(BOM)) fail(`${ctx}: no BOM placed`);
    const compact = signJws(record, "issuer", h, p, issuer);
    if (!evaluate(record, major, ctx).valid) fail(`${ctx}: the Ed25519 layer must accept the honest signature`);
    const c = [];
    v1Case({
      id: `grant-verify-v${major}-bom-${label}`,
      family: c,
      major,
      surface: "verify_grant",
      input: { ...t.input, compact, public_key: b64u(issuer.publicKey) },
      verdict: { valid: false, rule: NO_NORMALIZATION_RULE, reason: "bom", kind: "json" },
      validExpected: {},
      construction: construction("issuer", issuer.keyLabel, `honest/leading-u+feff-${label}`),
      caseClass,
    });
    return c[0];
  });
}

// ---- e2e: envelope (issuer key and holder JWK) -------------------------------------------------

function envelopeBuilder(major) {
  const t = templateCase(...TEMPLATES.envelope[major]);
  const grant = splitCompact(t.input.grant, `envelope v${major} grant`);
  const proof = splitCompact(t.input.proof, `envelope v${major} proof`);
  const exp = t.input.expected;
  if (requestDigest(major, exp.operation, exp.cast_arguments) !== proof.payload.ba_req) {
    fail(`envelope v${major}: recomputed ba_req != template (request digest reimplementation drifted)`);
  }
  if (b64u(sha256(Buffer.from(t.input.grant, "ascii"))) !== proof.payload.ath) fail(`envelope v${major}: ath rule drifted`);
  return (issuer, holder, castArguments = exp.cast_arguments) => {
    const record = newRecord();
    record.keys.push({ role: "issuer", publicKey: issuer.publicKey });
    record.keys.push({ role: "holder", publicKey: holder.publicKey });
    const grantPayload = { ...grant.payload, cnf: { jkt: thumbprint(holder.publicKey) } };
    const grantCompact = signJws(record, "issuer", grant.header, grantPayload, issuer);
    const proofHeader = { ...proof.header, jwk: { ...proof.header.jwk, x: b64u(holder.publicKey) } };
    const proofPayload = {
      ...proof.payload,
      ath: b64u(sha256(Buffer.from(grantCompact, "ascii"))),
      ba_req: requestDigest(major, exp.operation, castArguments),
    };
    const proofCompact = signJws(record, "holder", proofHeader, proofPayload, holder);
    const input = {
      ...t.input,
      grant: grantCompact,
      proof: proofCompact,
      expected: { ...exp, cast_arguments: castArguments, trusted_issuer: { ...exp.trusted_issuer, public_key: b64u(issuer.publicKey) } },
    };
    const { verdict: _drop, ...validExpected } = t.expected;
    return { record, input, validExpected };
  };
}

function familyEnvelope(major) {
  const cases = [];
  const build = envelopeBuilder(major);
  const baseline = { id: "honest", intent: "valid", candidate: () => honestSigner(honestKey("issuer")) };
  const runs = [
    ["issuer", baseline, (s) => build(s, honestSigner(honestKey("holder")))],
    ...signerScenarios(`envelope-v${major}-issuer`, "issuer").map((sc) => ["issuer", sc, (s) => build(s, honestSigner(honestKey("holder")))]),
    ...signerScenarios(`envelope-v${major}-holder`, "holder").map((sc) => ["holder", sc, (s) => build(honestSigner(honestKey("issuer")), s)]),
  ];
  for (const [position, scenario, builder] of runs) {
    const ctx = `envelope v${major} ${position} ${scenario.id}`;
    const r = runScenario(scenario, builder, ctx);
    r.verdict = evaluate(r.record, major, ctx);
    checkIntent(scenario, r, major, ctx);
    v1Case({
      id: scenario.id === "honest" ? `envelope-v${major}-honest` : `envelope-v${major}-${position}-${scenario.id}`,
      family: cases,
      major,
      surface: "check_envelope",
      input: r.input,
      verdict: r.verdict,
      validExpected: r.validExpected,
      construction: construction(scenario.id === "honest" ? "issuer+holder" : position, r.signer.keyLabel, r.signer.sigLabel),
      note: scenario.note,
    });
  }
  return cases;
}

// ---- e2e: boundary anchor --------------------------------------------------------------------

function anchorBuilder(major) {
  const t = templateCase(...TEMPLATES.anchor[major]);
  const { header, payload } = splitCompact(t.input.compact, `anchor v${major}`);
  return (archive) => {
    const record = newRecord();
    record.keys.push({ role: "archive", publicKey: archive.publicKey });
    const fp = thumbprint(archive.publicKey);
    const compact = signJws(record, "archive", header, { ...payload, key_fingerprint: fp }, archive);
    const input = {
      ...t.input,
      compact,
      expected: { ...t.input.expected, key_fingerprint: fp },
      key: { ...t.input.key, public_key: b64u(archive.publicKey) },
    };
    const { verdict: _drop, ...validExpected } = t.expected;
    return { record, input, validExpected };
  };
}

function familyAnchor(major) {
  const cases = [];
  const build = anchorBuilder(major);
  const baseline = { id: "honest", intent: "valid", candidate: () => honestSigner(honestKey("archive-a")) };
  for (const scenario of [baseline, ...signerScenarios(`anchor-v${major}-archive`, "archive-a")]) {
    const ctx = `boundary-anchor v${major} ${scenario.id}`;
    const r = runScenario(scenario, build, ctx);
    r.verdict = evaluate(r.record, major, ctx);
    checkIntent(scenario, r, major, ctx);
    v1Case({
      id: `boundary-anchor-v${major}-archive-${scenario.id}`,
      family: cases,
      major,
      surface: "verify_historical_anchor",
      input: r.input,
      verdict: r.verdict,
      validExpected: r.validExpected,
      construction: construction("archive", r.signer.keyLabel, r.signer.sigLabel),
      note: scenario.note,
    });
  }
  return cases;
}

// ---- e2e: key transition (current key signs; next key is carried) ----------------------------

function transitionBuilder(major) {
  const t = templateCase(...TEMPLATES.transition[major]);
  const { header, payload } = splitCompact(t.input.compact, `transition v${major}`);
  return (current, nextPublicKey) => {
    const record = newRecord();
    record.keys.push({ role: "current", publicKey: current.publicKey });
    record.keys.push({ role: "next", publicKey: nextPublicKey });
    const fromFp = thumbprint(current.publicKey);
    const toFp = thumbprint(nextPublicKey);
    const compact = signJws(record, "current", header, { ...payload, from_key_fingerprint: fromFp, to_key_fingerprint: toFp }, current);
    const input = {
      ...t.input,
      compact,
      current_key: { ...t.input.current_key, public_key: b64u(current.publicKey) },
      next_key: { ...t.input.next_key, public_key: b64u(nextPublicKey) },
      expected: { ...t.input.expected, current_key_fingerprint: fromFp, next_key_fingerprint: toFp },
    };
    const { verdict: _drop, ...validExpected } = t.expected;
    return { record, input, validExpected };
  };
}

function familyTransition(major) {
  const cases = [];
  const build = transitionBuilder(major);
  const next = () => honestKey("archive-b").publicKey;
  const baseline = { id: "honest", intent: "valid", candidate: () => honestSigner(honestKey("archive-a")) };
  for (const scenario of [baseline, ...signerScenarios(`transition-v${major}-current`, "archive-a")]) {
    const ctx = `key-transition v${major} current ${scenario.id}`;
    const r = runScenario(scenario, (s) => build(s, next()), ctx);
    r.verdict = evaluate(r.record, major, ctx);
    checkIntent(scenario, r, major, ctx);
    v1Case({
      id: scenario.id === "honest" ? `key-transition-v${major}-honest` : `key-transition-v${major}-current-${scenario.id}`,
      family: cases,
      major,
      surface: "verify_key_transition",
      input: r.input,
      verdict: r.verdict,
      validExpected: r.validExpected,
      construction: construction(scenario.id === "honest" ? "current+next" : "current", r.signer.keyLabel, r.signer.sigLabel),
      note: scenario.note,
    });
  }
  for (const d of dataKeyScenarios(`transition-v${major}-next`)) {
    const ctx = `key-transition v${major} next ${d.id}`;
    const r = build(honestSigner(honestKey("archive-a")), d.key);
    const verdict = evaluateCarried(r.record, major, ctx, d.note === TORSION_NOTE);
    v1Case({
      id: `key-transition-v${major}-next-${d.id}`,
      family: cases,
      major,
      surface: "verify_key_transition",
      input: r.input,
      verdict,
      validExpected: r.validExpected,
      construction: construction("next", d.keyLabel, "honest"),
      note: d.note,
    });
  }
  return cases;
}

// ---- e2e: anchored export (a weak key anywhere in the key chain) -------------------------------

function frame(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function exportBuilder(major) {
  const t = templateCase(...TEMPLATES.export[major]);
  const chunks = t.input.chunks.map((c) => Buffer.from(c, "base64url"));
  const archive = Buffer.concat(chunks);
  const prefix = Buffer.from(`BAP${major}-ARCHIVE\0EXPORT\0`, "binary");
  if (!archive.subarray(0, prefix.length).equals(prefix)) fail(`export v${major}: prefix`);
  let cursor = prefix.length;
  const readFrame = () => {
    const length = archive.readUInt32BE(cursor);
    const bytes = archive.subarray(cursor + 4, cursor + 4 + length);
    cursor += 4 + length;
    return bytes;
  };
  const headerBytes = readFrame();
  const header = JSON.parse(headerBytes.toString("utf8"));
  const start = readFrame().toString("ascii");
  const transitions = [];
  for (let i = 0; i < header.transition_count; i += 1) transitions.push(readFrame().toString("ascii"));
  const rows = [];
  for (let i = 0; i < header.row_count; i += 1) rows.push(Buffer.from(readFrame()));
  const end = readFrame().toString("ascii");
  if (cursor !== archive.length || transitions.length !== 1) fail(`export v${major}: template shape`);
  const rebuilt = Buffer.concat([prefix, frame(headerBytes), frame(Buffer.from(start)), frame(Buffer.from(transitions[0])), ...rows.map(frame), frame(Buffer.from(end))]);
  if (!rebuilt.equals(archive) || b64u(sha256(rebuilt)) !== t.input.expected.digest) fail(`export v${major}: template re-framing drifted`);
  const startParts = splitCompact(start, `export v${major} start`);
  const transitionParts = splitCompact(transitions[0], `export v${major} transition`);
  const endParts = splitCompact(end, `export v${major} end`);
  return ({ startSigner, transitionSigner, endSigner }) => {
    const record = newRecord();
    const k0 = startSigner.publicKey;
    const k1 = endSigner.publicKey;
    if (!transitionSigner.publicKey.equals(k0)) fail("export: transition signer must be the start key");
    record.keys.push({ role: "key0", publicKey: k0 });
    record.keys.push({ role: "key1", publicKey: k1 });
    const fp0 = thumbprint(k0);
    const fp1 = thumbprint(k1);
    const startCompact = signJws(record, "key0", startParts.header, { ...startParts.payload, key_fingerprint: fp0 }, startSigner);
    const transitionCompact = signJws(record, "key0", transitionParts.header, { ...transitionParts.payload, from_key_fingerprint: fp0, to_key_fingerprint: fp1 }, transitionSigner);
    const endCompact = signJws(record, "key1", endParts.header, { ...endParts.payload, key_fingerprint: fp1 }, endSigner);
    const pieces = [prefix, frame(headerBytes), frame(Buffer.from(startCompact)), frame(Buffer.from(transitionCompact)), ...rows.map(frame), frame(Buffer.from(endCompact))];
    const bytes = Buffer.concat(pieces);
    const exp = t.input.expected;
    const input = {
      ...t.input,
      chunks: pieces.map(b64u),
      keys: [
        { ...t.input.keys[0], public_key: b64u(k0) },
        { ...t.input.keys[1], public_key: b64u(k1) },
      ],
      expected: {
        ...exp,
        digest: b64u(sha256(bytes)),
        start_anchor: { ...exp.start_anchor, key_fingerprint: fp0 },
        end_anchor: { ...exp.end_anchor, key_fingerprint: fp1 },
        transitions: [{ ...exp.transitions[0], current_key_fingerprint: fp0, next_key_fingerprint: fp1 }],
      },
    };
    const { verdict: _drop, ...validExpected } = t.expected;
    return { record, input, validExpected };
  };
}

function familyExport(major) {
  const cases = [];
  const build = exportBuilder(major);
  const a = () => honestSigner(honestKey("archive-a"));
  const b = () => honestSigner(honestKey("archive-b"));
  const pos = `export-v${major}`;
  const scenarios = [
    { id: "honest", intent: "valid", signers: () => ({ startSigner: a(), transitionSigner: a(), endSigner: b() }), position: "key0+key1" },
    { id: "key1-identity-forged", intent: "a-small-order", signers: () => ({ startSigner: a(), transitionSigner: a(), endSigner: forgedZeroSigner(IDENTITY_BYTES, "small-order-0") }), position: "key1" },
    { id: "key1-noncanonical-identity-alias-forged", intent: "a-noncanonical", signers: () => ({ startSigner: a(), transitionSigner: a(), endSigner: forgedZeroSigner(ALIAS_IDENTITY_Y1P, "y-p-plus-1") }), position: "key1" },
    {
      id: "key0-identity-forged",
      intent: "a-small-order",
      signers: () => {
        const f = forgedZeroSigner(IDENTITY_BYTES, "small-order-0");
        return { startSigner: f, transitionSigner: f, endSigner: b() };
      },
      position: "key0",
    },
    {
      id: "key1-small-order-order8-forged",
      intent: "a-small-order",
      signers: () => {
        const so = SMALL_ORDER.find((s) => s.order === 8);
        return { startSigner: a(), transitionSigner: a(), endSigner: forgedIsolatedSigner(so.bytes, so.label, `${pos}/key1-order8`) };
      },
      position: "key1",
    },
    {
      id: "key1-torsion-variant",
      intent: "valid",
      note: TORSION_NOTE,
      signers: () => ({ startSigner: a(), transitionSigner: a(), endSigner: mixedBothSigner(noteKey(mixedKey("archive-b", 1))) }),
      position: "key1",
    },
    { id: "end-anchor-s-plus-l", intent: "s-range", signers: () => ({ startSigner: a(), transitionSigner: a(), endSigner: scalarPlusLSigner(honestKey("archive-b"), "s-plus-l") }), position: "key1" },
    {
      id: "end-anchor-identity-r",
      intent: "r-small-order",
      signers: () => ({ startSigner: a(), transitionSigner: a(), endSigner: keyHolderFixedRSigner(honestKey("archive-b"), IDENTITY_BYTES, "key-holder-identity-r", { requireUngated: true }) }),
      position: "key1",
    },
  ];
  for (const scenario of scenarios) {
    const ctx = `anchored-export v${major} ${scenario.id}`;
    const signers = scenario.signers();
    let r;
    try {
      r = build(signers);
    } catch (error) {
      if (error instanceof Retry) fail(`${ctx}: no construction`);
      throw error;
    }
    r.verdict = evaluate(r.record, major, ctx);
    checkIntent(scenario, r, major, ctx);
    v1Case({
      id: `anchored-export-v${major}-${scenario.id}`,
      family: cases,
      major,
      surface: "verify_anchored_export",
      input: r.input,
      verdict: r.verdict,
      validExpected: r.validExpected,
      construction: construction(scenario.position, `${signers.startSigner.keyLabel} -> ${signers.endSigner.keyLabel}`, `${signers.startSigner.sigLabel}/${signers.endSigner.sigLabel}`),
      note: scenario.note,
    });
  }
  return cases;
}

// ---- e2e: local-loopback HTTP proof (holder key) -----------------------------------------------

function familyLoopback() {
  const root = "priv/conformance/application-profiles/local-loopback-http/v1";
  const profile = readJson(`${root}/profile.json`);
  const grant = splitCompact(profile.grant_compact, "loopback grant");
  const proofTemplate = profile.proofs.ipv4;
  const proof = splitCompact(proofTemplate.compact, "loopback proof");
  const req = profile.request;
  if (requestDigest(1, req.operation, req.cast_arguments) !== proof.payload.ba_req) fail("loopback: ba_req recompute drifted");
  const issuer = () => honestSigner(honestKey("loopback-issuer"));
  const build = (holder) => {
    const record = newRecord();
    const issuerSigner = issuer();
    record.keys.push({ role: "issuer", publicKey: issuerSigner.publicKey });
    record.keys.push({ role: "holder", publicKey: holder.publicKey });
    const grantCompact = signJws(record, "issuer", grant.header, { ...grant.payload, cnf: { jkt: thumbprint(holder.publicKey) } }, issuerSigner);
    const proofCompact = signJws(
      record,
      "holder",
      { ...proof.header, jwk: { ...proof.header.jwk, x: b64u(holder.publicKey) } },
      { ...proof.payload, ath: b64u(sha256(Buffer.from(grantCompact, "ascii"))) },
      holder,
    );
    return { record, grantCompact, proofCompact, issuerPublicKey: issuerSigner.publicKey };
  };
  const cases = [];
  const baseline = { id: "honest", intent: "valid", candidate: () => honestSigner(honestKey("holder")) };
  for (const scenario of [baseline, ...signerScenarios("loopback-holder", "holder")]) {
    const ctx = `loopback holder ${scenario.id}`;
    const r = runScenario(scenario, build, ctx);
    r.verdict = evaluate(r.record, 1, ctx);
    checkIntent(scenario, r, 1, ctx);
    const holderAcceptable = Ref.acceptablePublicKey(r.signer.publicKey).valid;
    const c = {
      id: `loopback-holder-${scenario.id}`,
      rule: r.verdict.rule,
      surface: "local_loopback_http",
      grant: r.grantCompact,
      compact: r.proofCompact,
      decode_local: holderAcceptable,
      decode_standard: false,
      envelope_local: r.verdict.valid,
      issuer: { ...profile.issuer, public_key: b64u(r.issuerPublicKey) },
      request: req,
      nonce: proofTemplate.nonce,
      target_uri: proofTemplate.target_uri,
      construction: construction("holder", r.signer.keyLabel, r.signer.sigLabel),
    };
    if (scenario.note) c.note = scenario.note;
    cases.push(c);
  }
  return cases;
}

// ---- e2e: role attestation (attestor signs; subject key is carried) ----------------------------

function familyRoleAttestation() {
  const root = "priv/conformance/attestation-profiles/role-attestation/v1";
  const profile = readJson(`${root}/profile.json`);
  const t = templateCase(`${root}/attestation-cases.json`, "issuer-valid");
  const { header, payload } = splitCompact(t.compact, "role attestation");
  const build = (attestor, subjectPublicKey) => {
    const record = newRecord();
    record.keys.push({ role: "attestor", publicKey: attestor.publicKey });
    record.keys.push({ role: "subject", publicKey: subjectPublicKey });
    const compact = signJws(record, "attestor", header, { ...payload, public_key: b64u(subjectPublicKey) }, attestor);
    return { record, compact, subjectPublicKey };
  };
  const pushCase = (cases, id, r, verdict, position, keyLabel, sigLabel, note) => {
    const subjectAcceptable = Ref.acceptablePublicKey(r.subjectPublicKey).valid;
    const c = {
      id,
      rule: verdict.rule,
      surface: "role_attestation",
      compact: r.compact,
      decode: subjectAcceptable,
      verify: verdict.valid,
      attestor: { ...profile.attestor, public_key: b64u(r.record.signatures[0].publicKey) },
      subject: { ...profile.subject, public_key: b64u(r.subjectPublicKey) },
      now: profile.now,
      construction: construction(position, keyLabel, sigLabel),
    };
    if (note) c.note = note;
    cases.push(c);
  };
  const cases = [];
  const subject = () => honestKey("subject").publicKey;
  const baseline = { id: "honest", intent: "valid", candidate: () => honestSigner(honestKey("attestor")) };
  for (const scenario of [baseline, ...signerScenarios("ra1-attestor", "attestor")]) {
    const ctx = `ra1 attestor ${scenario.id}`;
    const r = runScenario(scenario, (s) => build(s, subject()), ctx);
    r.verdict = evaluate(r.record, 1, ctx);
    checkIntent(scenario, r, 1, ctx);
    pushCase(cases, scenario.id === "honest" ? "ra1-honest" : `ra1-attestor-${scenario.id}`, r, r.verdict, scenario.id === "honest" ? "attestor+subject" : "attestor", r.signer.keyLabel, r.signer.sigLabel, scenario.note);
  }
  for (const d of dataKeyScenarios("ra1-subject")) {
    const ctx = `ra1 subject ${d.id}`;
    const r = build(honestSigner(honestKey("attestor")), d.key);
    const verdict = evaluateCarried(r.record, 1, ctx, d.note === TORSION_NOTE);
    pushCase(cases, `ra1-subject-${d.id}`, r, verdict, "subject", d.keyLabel, "honest", d.note);
  }
  return cases;
}

// ---- e2e: content assertion (attestor key) ------------------------------------------------------

function familyContentAssertion() {
  const root = "priv/conformance/attestation-profiles/content-assertion/v1";
  const profile = readJson(`${root}/profile.json`);
  const t = templateCase(`${root}/assertion-structure-cases.json`, "valid-genesis");
  if ((t.attestor ?? "primary") !== "primary" || t.expected_overrides) fail("ca1 template shape");
  const { header, payload } = splitCompact(t.compact, "content assertion");
  const build = (attestor) => {
    const record = newRecord();
    record.keys.push({ role: "attestor", publicKey: attestor.publicKey });
    const compact = signJws(record, "attestor", header, payload, attestor);
    return { record, compact };
  };
  const cases = [];
  const baseline = { id: "honest", intent: "valid", candidate: () => honestSigner(honestKey("attestor")) };
  for (const scenario of [baseline, ...signerScenarios("ca1-attestor", "attestor")]) {
    const ctx = `ca1 attestor ${scenario.id}`;
    const r = runScenario(scenario, build, ctx);
    r.verdict = evaluate(r.record, 1, ctx);
    checkIntent(scenario, r, 1, ctx);
    const c = {
      id: `ca1-attestor-${scenario.id}`,
      rule: r.verdict.rule,
      surface: "content_assertion",
      class: r.verdict.valid ? "valid" : "invalid_signature",
      compact: r.compact,
      expected: { decode: "valid", verify: r.verdict.valid ? "valid" : "invalid" },
      attestor: { ...profile.attestors.primary, public_key: b64u(r.signer.publicKey) },
      expected_context: profile.expected,
      construction: construction("attestor", r.signer.keyLabel, r.signer.sigLabel),
    };
    if (scenario.note) c.note = scenario.note;
    cases.push(c);
  }
  return cases;
}

// ---- jwk and key acceptance --------------------------------------------------------------------

function keySet() {
  const set = [];
  for (const name of ["issuer", "holder", "signer"]) set.push({ id: `honest-${name}`, key: honestKey(name).publicKey, label: honestKey(name).label, torsionFree: true });
  for (let i = 1; i < 8; i += 1) {
    const k = mixedKey("signer", i);
    set.push({ id: `torsion-variant-${i}`, key: k.publicKey, label: k.label, torsionFree: false, note: TORSION_NOTE });
  }
  for (const so of SMALL_ORDER) set.push({ id: `small-order-${so.index}-order${so.order}`, key: so.bytes, label: so.label, torsionFree: false });
  for (const nc of NONCANONICAL) set.push({ id: `noncanonical-${nc.label}`, key: nc.bytes, label: `${nc.label} (${nc.decodes})`, torsionFree: false });
  for (const oc of OFF_CURVE) set.push({ id: oc.label, key: oc.bytes, label: oc.label, torsionFree: false });
  return set;
}

function familyKeyAcceptance() {
  const acceptable = [];
  const torsion = [];
  const set = keySet();
  const present = new Set(set.map((k) => hex(k.key)));
  for (const [label, key] of notedKeys) {
    if (present.has(hex(key))) continue;
    present.add(hex(key));
    set.push({ id: `noted-${label.replace(/^torsion-variant:/, "").replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`, key, label, torsionFree: false, note: TORSION_NOTE });
  }
  set.push({ id: "width-31", key: Buffer.alloc(31, 0x11), label: "31 bytes", torsionFree: false });
  set.push({ id: "width-33", key: Buffer.alloc(33, 0x11), label: "33 bytes", torsionFree: false });
  for (const k of set) {
    const a = k.key.length === 32 ? keyVerdict(k.key, `key-acceptance ${k.id}`) : Ref.acceptablePublicKey(k.key);
    const tf = torsionVerdict(k.key, k.torsionFree, `torsion-free ${k.id}`);
    const base = { input: { public_key: b64u(k.key) }, construction: { key: k.label } };
    const ac = { id: `acceptable-${k.id}`, rule: keyRule(1), surface: "ed25519.acceptable_public_key", ...base, expected: { verdict: a.valid ? "valid" : "invalid" } };
    if (a.valid && k.note) ac.note = k.note;
    acceptable.push(ac);
    const tc = { id: `torsion-free-${k.id}`, rule: torsionRule(1), surface: "ed25519.torsion_free", ...base, expected: { verdict: tf.valid ? "valid" : "invalid" } };
    if (k.note) tc.note = k.note;
    torsion.push(tc);
  }
  return { acceptable, torsion };
}

function familyJwk() {
  const bySurface = {
    "jwk.encode_public": [],
    "jwk.decode_public": [],
    "jwk.thumbprint": [],
    "jwk.thumbprint_preimage": [],
    "jwk.thumbprint_raw": [],
    "jwk.public_key_thumbprint_raw": [],
  };
  for (const k of keySet()) {
    const v = keyVerdict(k.key, `jwk ${k.id}`);
    const verdict = v.valid ? { valid: true, rule: keyRule(1), reason: "valid" } : { valid: false, rule: keyRule(1), reason: v.reason, kind: "key" };
    const text = jwkText(k.key);
    const pk = b64u(k.key);
    const shapes = {
      "jwk.encode_public": [{ public_key: pk }, { encoded: text }],
      "jwk.decode_public": [{ text }, { public_key: pk }],
      "jwk.thumbprint": [{ text }, { thumbprint: thumbprint(k.key) }],
      "jwk.thumbprint_preimage": [{ text }, { preimage: text }],
      "jwk.thumbprint_raw": [{ text }, {}],
      "jwk.public_key_thumbprint_raw": [{ public_key: pk }, {}],
    };
    for (const [surface, [input, validExpected]] of Object.entries(shapes)) {
      v1Case({
        id: `jwk-${surface.slice(4).replaceAll("_", "-")}-${k.id}`,
        family: bySurface[surface],
        major: 1,
        surface,
        input,
        verdict,
        validExpected,
        construction: { key: k.label, position: "jwk.x", signature: "none" },
        note: v.valid ? k.note : undefined,
      });
    }
  }
  return bySurface;
}

// ---- primitive verify_strict --------------------------------------------------------------------

// RFC 8032 section 7.1 TEST 1-3 (published public key, message and signature; no secret).
const RFC8032_VECTORS = [
  ["test-1", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"],
  ["test-2", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"],
  ["test-3", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"],
];

function primitiveCase(cases, id, publicKey, signature, message, constructionMeta, extra = {}) {
  const v = signatureVerdict(publicKey, signature, message, `primitive ${id}`);
  const c = {
    id,
    rule: signingRule(1, v.valid ? "valid" : v.reason),
    surface: "ed25519.verify_strict",
    input: { message: b64u(message), public_key: b64u(publicKey), signature: b64u(signature) },
    expected: { verdict: v.valid ? "valid" : "invalid" },
    construction: constructionMeta,
    ...extra,
  };
  cases.push(c);
  return v;
}

function familyPrimitive() {
  const cases = [];
  const expect = (id, v, intent) => {
    const want = intent === "valid";
    if (v.valid !== want || (!want && REASON_RULE[v.reason] !== REASON_RULE[intent])) fail(`primitive ${id}: intends ${intent}, arithmetic gives ${v.valid} (${v.reason})`);
  };
  const sign = (signer, message) => {
    const sig = signer.sign(message);
    if (sig === null) fail(`primitive: no construction for ${signer.sigLabel}`);
    if (signer.forgery && !Ref.verifyUngatedCofactorless(signer.publicKey, sig, message)) fail(`primitive: ${signer.sigLabel} not a real forgery`);
    if (signer.cofactoredOnly && !verifyCofactored(signer.publicKey, sig, message)) fail(`primitive: ${signer.sigLabel} not cofactored-accepted`);
    return sig;
  };
  for (const [name, pk, msg, sig] of RFC8032_VECTORS) {
    expect(name, primitiveCase(cases, `rfc8032-${name}`, fromHex(pk), fromHex(sig), fromHex(msg), { key: "RFC 8032 section 7.1", position: "verify", signature: name }), "valid");
  }
  const signer = honestKey("signer");
  const m = (label) => Buffer.from(`bap-strict-ed25519 primitive ${label}`, "utf8");
  const run = (id, s, message, intent, extra) => {
    const sig = sign(s, message);
    expect(id, primitiveCase(cases, id, s.publicKey, sig, message, { key: s.keyLabel, position: "verify", signature: s.sigLabel }, extra), intent);
  };
  run("honest", honestSigner(signer), m("honest"), "valid");
  // R small-order and S = 0 exists only for some messages (k decides [k]A): search the message.
  const runSearchingMessage = (id, s, label, intent) => {
    for (let n = 0; n < 256; n += 1) {
      const message = m(`${label}/${n}`);
      if (s.sign(message) !== null) return run(id, s, message, intent);
    }
    fail(`primitive ${id}: no construction`);
  };
  for (const so of SMALL_ORDER) runSearchingMessage(`forged-small-order-a-${so.index}-rs0`, forgedZeroSigner(so.bytes, so.label), `rs0-${so.index}`, "a-small-order");
  for (const so of SMALL_ORDER) run(`iso-small-order-a-${so.index}`, forgedIsolatedSigner(so.bytes, so.label, `primitive/iso-a/${so.index}`), m(`iso-${so.index}`), "a-small-order");
  for (const nc of NONCANONICAL_SMALL) runSearchingMessage(`forged-noncanonical-a-${nc.label}-rs0`, forgedZeroSigner(nc.bytes, nc.label), `nc-rs0-${nc.label}`, "a-noncanonical");
  for (const nc of NONCANONICAL_SMALL) run(`iso-noncanonical-a-${nc.label}`, forgedIsolatedSigner(nc.bytes, nc.label, `primitive/iso-nc/${nc.label}`), m(`iso-nc-${nc.label}`), "a-noncanonical");
  for (const nc of NONCANONICAL.filter((e) => e.decodes !== "small-order")) {
    expect(`noncanonical-a-${nc.label}`, primitiveCase(cases, `noncanonical-a-${nc.label}`, nc.bytes, Buffer.alloc(64), m(`nc-${nc.label}`), { key: `${nc.label} (${nc.decodes})`, position: "verify", signature: "zero" }), "a-noncanonical");
  }
  for (const [label, alias] of [["y-p-plus-1", ALIAS_IDENTITY_Y1P], ["x0-sign-identity", ALIAS_IDENTITY_X0]]) {
    expect(`noncanonical-r-${label}-identity-a`, primitiveCase(cases, `noncanonical-r-${label}-identity-a`, IDENTITY_BYTES, Buffer.concat([alias, S_BYTES(0n)]), m(`ncr-${label}`), { key: "small-order-0", position: "verify", signature: `noncanonical-r-${label}-s0` }), "a-small-order");
    run(`honest-a-noncanonical-r-${label}`, keyHolderFixedRSigner(signer, alias, `key-holder-noncanonical-r-${label}`, { requireUngated: false }), m(`hncr-${label}`), "r-noncanonical");
  }
  run("honest-a-identity-r", keyHolderFixedRSigner(signer, IDENTITY_BYTES, "key-holder-identity-r", { requireUngated: true }), m("identity-r"), "r-small-order");
  // R of order 8 with S = k a: cofactored-only shape, rejected by the R rule first.
  run("honest-a-order8-r", keyHolderFixedRSigner(signer, SMALL_ORDER.find((s) => s.order === 8).bytes, "key-holder-order8-r", { requireUngated: false }), m("order8-r"), "r-small-order");
  for (let j = 0; j < 8; j += 1) {
    let done = false;
    for (let attempt = 0; attempt < 2048 && !done; attempt += 1) {
      const key = mixedKey(`primitive/mixed-a-small-r-${j}/${Math.floor(attempt / 7)}`, 1 + (attempt % 7));
      const s = keyHolderFixedRSigner(key, SMALL_ORDER[j].bytes, `key-holder-small-r-${j}`, { requireUngated: true });
      const message = m(`mixed-a-small-r-${j}`);
      if (s.sign(message) === null) continue;
      run(`mixed-a-small-r-${j}`, s, message, "r-small-order");
      done = true;
    }
    if (!done) fail(`primitive mixed-a-small-r-${j}: no construction`);
  }
  // Small-order A (order 8) with a mixed-order R: no private key needed.
  {
    const so = SMALL_ORDER.find((s) => s.order === 8);
    run("small-a-mixed-r", forgedIsolatedSigner(so.bytes, so.label, "primitive/small-a-mixed-r"), m("small-a-mixed-r"), "a-small-order");
  }
  run("honest-a-mixed-r", mixedRSigner(signer), m("mixed-r"), "equation");
  // Mixed A, honest-shaped R = [r]B, k with [k]T != O: passes the cofactored equation only.
  {
    let done = false;
    for (let attempt = 0; attempt < 64 && !done; attempt += 1) {
      const key = mixedKey("signer", 1);
      const message = m(`mixed-a-cofactored-only/${attempt}`);
      const s = {
        publicKey: key.publicKey,
        keyLabel: key.label,
        sigLabel: "key-holder-mixed-a-prime-r",
        cofactoredOnly: true,
        sign(msg) {
          const r = nonceScalar(key, msg, "cofactored-only");
          const rBytes = Ref.encodePoint(Ref.multiply(r, Ref.BASE));
          const k = Ref.challenge(rBytes, key.publicKey, msg);
          if (k % 8n === 0n) return null;
          return Buffer.concat([rBytes, S_BYTES((r + k * key.scalar) % Ref.L)]);
        },
      };
      if (s.sign(message) === null) continue;
      run("mixed-a-cofactored-only", s, message, "equation");
      done = true;
    }
    if (!done) fail("primitive mixed-a-cofactored-only: no construction");
  }
  run("mixed-a-mixed-r-both", mixedBothSigner(noteKey(mixedKey("signer", 1))), m("mixed-both"), "valid", { note: TORSION_NOTE });
  run("s-plus-l", scalarPlusLSigner(signer, "s-plus-l"), m("honest"), "s-range");
  run("s-plus-max-l", scalarPlusLSigner(signer, "s-plus-max-l"), m("honest"), "s-range");
  expect("s-equals-l-identity", primitiveCase(cases, "s-equals-l-identity", IDENTITY_BYTES, Buffer.concat([IDENTITY_BYTES, S_BYTES(Ref.L)]), m("s-equals-l"), { key: "small-order-0", position: "verify", signature: "identity-r-s-l" }), "a-small-order");
  {
    const honest = Ref.signHonest(signer.seed, m("s-max"), signer.publicKey);
    expect("s-all-ones", primitiveCase(cases, "s-all-ones", signer.publicKey, Buffer.concat([honest.subarray(0, 32), Buffer.alloc(32, 0xff)]), m("s-max"), { key: signer.label, position: "verify", signature: "s-2^256-1" }), "s-range");
    const flipped = Buffer.from(honest);
    flipped[0] ^= 0x01;
    expect("honest-tampered-r", primitiveCase(cases, "honest-tampered-r", signer.publicKey, flipped, m("s-max"), { key: signer.label, position: "verify", signature: "honest-r-byte0-xor1" }), "equation");
  }
  for (const oc of OFF_CURVE) {
    const honest = Ref.signHonest(signer.seed, m("offcurve"), signer.publicKey);
    expect(`offcurve-a-${oc.label}`, primitiveCase(cases, `offcurve-a-${oc.label}`, oc.bytes, honest, m("offcurve"), { key: oc.label, position: "verify", signature: "honest-under-other-key" }), "a-off-curve");
    expect(`offcurve-r-${oc.label}`, primitiveCase(cases, `offcurve-r-${oc.label}`, signer.publicKey, Buffer.concat([oc.bytes, honest.subarray(32)]), m("offcurve"), { key: signer.label, position: "verify", signature: `r-${oc.label}` }), "equation");
  }
  expect("width-public-key-31", primitiveCase(cases, "width-public-key-31", signer.publicKey.subarray(0, 31), Ref.signHonest(signer.seed, m("w"), signer.publicKey), m("w"), { key: "31 bytes", position: "verify", signature: "honest" }), "width");
  expect("width-signature-63", primitiveCase(cases, "width-signature-63", signer.publicKey, Ref.signHonest(signer.seed, m("w"), signer.publicKey).subarray(0, 63), m("w"), { key: signer.label, position: "verify", signature: "63 bytes" }), "width");
  return cases;
}

// ---- named key-only forgeries (primitive family) ------------------------------------------------
// The construction stock cofactorless verifiers (Go crypto/ed25519, OTP, Node 22) accept with no
// private key: A of small order (or an alias of one), an ordinary prime-order R = [r]B and S = r.
// Then [S]B - [k]A = [r]B whenever [k]A = O, which holds once ord(A) divides k. Under the identity
// key every message works, so (a) is the literal R = B (the encoded base point), S = 1. Each vector
// is emitted once per contract major with that major's rule id (primitive cases carry no `major`
// field: the runners route a case with `major` to the contract dispatch); the case records that the ungated
// cofactorless equation accepts it, and the generator asserts node:crypto's raw backend accepts it
// on the Node 22 line (Node 24.19+ rejects small-order keys itself, so there it only reports).

const KEY_ONLY_MESSAGES = 3;
const BASE_BYTES = Ref.encodePoint(Ref.BASE);
const keyOnlyStats = { vectors: 0, rawNodeAccepts: 0 };

function keyOnlyCase(cases, major, id, publicKey, signature, message, keyLabel, sigLabel, intent) {
  if (!Ref.verifyUngatedCofactorless(publicKey, signature, message)) fail(`${id}: not accepted by the ungated cofactorless equation`);
  const v = signatureVerdict(publicKey, signature, message, `key-only ${id}`);
  if (v.valid || REASON_RULE[v.reason] !== REASON_RULE[intent]) fail(`${id}: intends ${intent}, arithmetic gives ${v.valid} (${v.reason})`);
  const raw = nodeEd25519Verify(publicKey, signature, message);
  keyOnlyStats.vectors += 1;
  if (raw) keyOnlyStats.rawNodeAccepts += 1;
  if (process.version.startsWith("v22.") && !raw) fail(`${id}: node:crypto ${process.version} raw backend rejects a key-only forgery`);
  cases.push({
    construction: { key: keyLabel, position: "verify", signature: sigLabel },
    expected: { verdict: "invalid" },
    id,
    input: { message: b64u(message), public_key: b64u(publicKey), signature: b64u(signature) },
    raw_cofactorless: "accept",
    rule: signingRule(major, v.reason),
    surface: "ed25519.verify_strict",
  });
}

function familyKeyOnly() {
  const cases = [];
  const keys = [
    ...SMALL_ORDER.map((so) => ({ label: so.label, bytes: so.bytes, intent: "a-small-order" })),
    ...NONCANONICAL_SMALL.map((nc) => ({ label: nc.label, bytes: nc.bytes, intent: "a-noncanonical" })),
  ];
  for (const major of [1, 2]) {
    for (let n = 0; n < KEY_ONLY_MESSAGES; n += 1) {
      const message = Buffer.from(`bap-strict-ed25519 identity A, R = B, S = 1, message ${n}`, "utf8");
      keyOnlyCase(cases, major, `key-only-v${major}-identity-a-basepoint-r-s1-${n}`, IDENTITY_BYTES, Buffer.concat([BASE_BYTES, S_BYTES(1n)]), message, "small-order-0", "basepoint-r-s1", "a-small-order");
    }
    for (const key of keys) {
      for (let n = 0; n < KEY_ONLY_MESSAGES; n += 1) {
        const message = Buffer.from(`bap-strict-ed25519 key-only ${key.label} message ${n}`, "utf8");
        let signature = null;
        for (let r = 1n; r <= 64n && signature === null; r += 1n) {
          const candidate = Buffer.concat([Ref.encodePoint(Ref.multiply(r, Ref.BASE)), S_BYTES(r)]);
          if (Ref.verifyUngatedCofactorless(key.bytes, candidate, message)) signature = candidate;
        }
        if (signature === null) fail(`key-only ${key.label} ${n}: no prime-order R construction`);
        keyOnlyCase(cases, major, `key-only-v${major}-${key.label}-prime-r-${n}`, key.bytes, signature, message, key.label, "prime-r-s-equals-r", key.intent);
      }
    }
  }
  return cases;
}

// ---- Taming the many EdDSAs (ed25519-speccheck cases.json, verbatim) ---------------------------

const SPECCHECK_SHA256 = "08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450";
const SPECCHECK_CASES_JSON =
  '[{"message":"8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6","pub_key":"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa","signature":"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"},' +
  '{"message":"9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79","pub_key":"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa","signature":"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},' +
  '{"message":"aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab","pub_key":"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43","signature":"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"},' +
  '{"message":"9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79","pub_key":"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d","signature":"9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"},' +
  '{"message":"e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c","pub_key":"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d","signature":"160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"},' +
  '{"message":"e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c","pub_key":"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d","signature":"21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"},' +
  '{"message":"85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40","pub_key":"442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623","signature":"e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"},' +
  '{"message":"85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40","pub_key":"442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623","signature":"8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22"},' +
  '{"message":"9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41","pub_key":"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43","signature":"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f"},' +
  '{"message":"9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41","pub_key":"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43","signature":"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908"},' +
  '{"message":"e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b","pub_key":"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","signature":"a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},' +
  '{"message":"39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f","pub_key":"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","signature":"a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"}]';

const SPECCHECK_PROVENANCE = {
  commit: "65519336fda78a3d016e947df6d82848aca0c9da",
  git_blob: "8686dcb7eef8b6abe36ca8fa9bb10de112e63774",
  license: "Apache-2.0",
  path: "cases.json",
  paper: "Chalkias, Garillot, Nikolaenko, Taming the many EdDSAs, SSR 2020, IACR ePrint 2020/1244",
  repository: "https://github.com/novifinancial/ed25519-speccheck",
  sha256: SPECCHECK_SHA256,
};

function familyTaming() {
  if (hex(sha256(Buffer.from(SPECCHECK_CASES_JSON, "utf8"))) !== SPECCHECK_SHA256) fail("speccheck cases.json bytes drifted");
  const vectors = JSON.parse(SPECCHECK_CASES_JSON);
  if (vectors.length !== 12) fail("speccheck: 12 vectors expected");
  const cases = [];
  vectors.forEach((v, index) => {
    const verdict = primitiveCase(
      cases,
      `taming-speccheck-${String(index).padStart(2, "0")}`,
      fromHex(v.pub_key),
      fromHex(v.signature),
      fromHex(v.message),
      { key: "ed25519-speccheck", position: "verify", signature: `case ${index}` },
      { source: { index, message: v.message, pub_key: v.pub_key, signature: v.signature } },
    );
    // Design 4.4: case 3 accepted at verify, every other case rejected.
    if (verdict.valid !== (index === 3)) fail(`speccheck case ${index}: arithmetic verdict ${verdict.valid} contradicts the design expectation`);
  });
  return cases;
}

// ---- JCS UTF-8 boundaries ----------------------------------------------------------------------

const JCS_CODE_POINTS = [0x3ff, 0x400, 0x47f, 0x480, 0x7ff, 0x7fff, 0x8000, 0x87ff, 0x8800, 0xfffd, 0xffff, 0xfffff, 0x100000, 0x10ffff];
const JCS_INVALID = [
  ["overlong-c0-80", "c080"],
  ["overlong-e0-80-80", "e08080"],
  ["overlong-f0-80-80-80", "f0808080"],
  ["surrogate-ed-a0-80", "eda080"],
  ["above-max-f4-90-80-80", "f4908080"],
  ["invalid-lead-f5-80-80-80", "f5808080"],
];

function familyJcs() {
  const out = { encode: [], digest: [], envelope: [], invalid: [], bom: [] };
  const builders = { 1: envelopeBuilder(1), 2: envelopeBuilder(2) };
  const cp = (n) => `u${n.toString(16).toUpperCase().padStart(4, "0")}`;
  const valid = () => ({ valid: true, rule: jcsRule(), reason: "valid" });
  for (const n of JCS_CODE_POINTS) {
    const s = String.fromCodePoint(n);
    const utf8 = Buffer.from(s, "utf8");
    if (utf8.toString("utf8") !== s || utf8.length !== (n < 0x80 ? 1 : n < 0x800 ? 2 : n < 0x10000 ? 3 : 4)) fail(`jcs ${cp(n)}: encoding`);
    const text = canonical({ value: s });
    v1Case({ id: `jcs-utf8-encode-${cp(n)}`, family: out.encode, major: 1, surface: "jcs.encode", input: { text }, verdict: valid(), validExpected: { encoded: text }, construction: { key: "none", position: "string", signature: "none" } });
    for (const major of [1, 2]) {
      const cast = { text: s };
      v1Case({
        id: `jcs-utf8-request-digest-v${major}-${cp(n)}`,
        family: out.digest,
        major,
        surface: "request_digest",
        input: { cast_arguments: cast, operation: "read" },
        verdict: valid(),
        validExpected: { digest: requestDigest(major, "read", cast) },
        construction: { key: "none", position: "cast_arguments", signature: "none" },
      });
      const r = builders[major](honestSigner(honestKey("issuer")), honestSigner(honestKey("holder")), cast);
      const verdict = evaluate(r.record, major, `jcs envelope v${major} ${cp(n)}`);
      if (!verdict.valid) fail(`jcs envelope v${major} ${cp(n)}: honest envelope rejected by arithmetic`);
      v1Case({
        id: `jcs-utf8-envelope-v${major}-${cp(n)}`,
        family: out.envelope,
        major,
        surface: "check_envelope",
        input: r.input,
        verdict: valid(),
        validExpected: r.validExpected,
        construction: { key: "honest:issuer/honest:holder", position: "cast_arguments", signature: "honest" },
      });
    }
  }
  // A leading U+FEFF in a string value and in a member name is preserved byte for byte.
  {
    const preserved = () => ({ valid: true, rule: NO_NORMALIZATION_RULE, reason: "valid" });
    const meta = { key: "none", position: "string", signature: "none" };
    const valueText = canonical({ value: BOM + "value" });
    const nameText = canonical({ [BOM + "name"]: "value" });
    const bothValue = { [BOM + "name"]: BOM + "value" };
    const bothText = canonical(bothValue);
    for (const text of [valueText, nameText, bothText]) {
      if (!Buffer.from(text, "utf8").includes(Buffer.from([0xef, 0xbb, 0xbf]))) fail("bom: EF BB BF missing");
    }
    v1Case({ id: "jcs-utf8-bom-encode-string-value", family: out.bom, major: 1, surface: "jcs.encode", input: { text: valueText }, verdict: preserved(), validExpected: { encoded: valueText }, construction: meta });
    v1Case({ id: "jcs-utf8-bom-encode-member-name", family: out.bom, major: 1, surface: "jcs.encode", input: { text: nameText }, verdict: preserved(), validExpected: { encoded: nameText }, construction: meta });
    v1Case({ id: "jcs-utf8-bom-decode-member-name-and-value", family: out.bom, major: 1, surface: "json.decode", input: { text: bothText }, verdict: preserved(), validExpected: { value: bothValue }, construction: meta });
    for (const major of [1, 2]) {
      v1Case({
        id: `jcs-utf8-bom-request-digest-v${major}`,
        family: out.bom,
        major,
        surface: "request_digest",
        input: { cast_arguments: bothValue, operation: "read" },
        verdict: preserved(),
        validExpected: { digest: requestDigest(major, "read", bothValue) },
        construction: { key: "none", position: "cast_arguments", signature: "none" },
      });
    }
  }
  for (const [label, seq] of JCS_INVALID) {
    const bytes = Buffer.concat([Buffer.from('"'), fromHex(seq), Buffer.from('"')]);
    if (Buffer.from(bytes.toString("utf8"), "utf8").equals(bytes)) fail(`jcs invalid ${label}: sequence is valid UTF-8`);
    const verdict = { valid: false, rule: jcsRule(), reason: "utf8", kind: "encoding" };
    for (const surface of ["jcs.encode", "json.decode"]) {
      v1Case({
        id: `jcs-utf8-${surface.replace(".", "-")}-${label}`,
        family: out.invalid,
        major: 1,
        surface,
        input: { base64url: b64u(bytes) },
        verdict,
        validExpected: {},
        construction: { key: "none", position: "string", signature: "none" },
      });
    }
  }
  return out;
}

// ---- differential (cross-language property file) -----------------------------------------------

const DIFFERENTIAL_COUNT = 1024;
const DIFFERENTIAL_MODES = ["plain", "plain", "plain", "plain", "plain", "plain", "fixup", "fixup", "fixup", "fixup", "s-plus-l", "s-plus-max-l", "small-a", "small-r", "noncanonical-a", "noncanonical-r"];
const TORSION_WEIGHTS = [0, 0, 0, 1, 2, 3, 4, 5, 6, 7];

function familyDifferential() {
  const cases = [];
  for (let n = 0; n < DIFFERENTIAL_COUNT; n += 1) {
    const rng = drbg(`differential/${n}`);
    const mode = DIFFERENTIAL_MODES[rng.pick(DIFFERENTIAL_MODES.length)];
    const jA = TORSION_WEIGHTS[rng.pick(TORSION_WEIGHTS.length)];
    let jR = TORSION_WEIGHTS[rng.pick(TORSION_WEIGHTS.length)];
    const key = jA === 0 ? honestKey(`differential-${n}`) : mixedKey(`differential-${n}`, jA);
    const message = Buffer.from(`diff-${n}`, "utf8");
    let publicKey = key.publicKey;
    let signature;
    const r = rng.scalar();
    const keyHolder = (rPoint) => {
      const rBytes = Ref.encodePoint(rPoint);
      const k = Ref.challenge(rBytes, publicKey, message);
      return Buffer.concat([rBytes, S_BYTES((r + k * key.scalar) % Ref.L)]);
    };
    if (mode === "plain" || mode === "s-plus-l" || mode === "s-plus-max-l") {
      signature = keyHolder(Ref.add(Ref.multiply(r, Ref.BASE), T[jR]));
      if (mode !== "plain") {
        const s = Ref.leToBig(signature.subarray(32));
        const k = mode === "s-plus-l" ? 1n : ((1n << 256n) - 1n - s) / Ref.L;
        signature = Buffer.concat([signature.subarray(0, 32), S_BYTES(s + k * Ref.L)]);
      }
    } else if (mode === "fixup") {
      for (let t = 0; t < 64; t += 1) {
        jR = rng.pick(8);
        signature = keyHolder(Ref.add(Ref.multiply(r, Ref.BASE), T[jR]));
        if (Ref.verifyUngatedCofactorless(publicKey, signature, message)) break;
      }
    } else if (mode === "small-a") {
      const so = SMALL_ORDER[rng.pick(8)];
      publicKey = so.bytes;
      signature = forgedIsolatedSigner(so.bytes, so.label, `differential/${n}`).sign(message);
    } else if (mode === "small-r") {
      jR = rng.pick(8);
      const rBytes = SMALL_ORDER[jR].bytes;
      const k = Ref.challenge(rBytes, publicKey, message);
      signature = Buffer.concat([rBytes, S_BYTES((k * key.scalar) % Ref.L)]);
    } else if (mode === "noncanonical-a") {
      const nc = NONCANONICAL_SMALL[rng.pick(NONCANONICAL_SMALL.length)];
      publicKey = nc.bytes;
      signature = forgedIsolatedSigner(nc.bytes, nc.label, `differential/${n}`).sign(message);
    } else if (mode === "noncanonical-r") {
      const alias = [ALIAS_IDENTITY_Y1P, ALIAS_IDENTITY_X0][rng.pick(2)];
      const k = Ref.challenge(alias, publicKey, message);
      signature = Buffer.concat([alias, S_BYTES((k * key.scalar) % Ref.L)]);
    }
    if (!signature) fail(`differential ${n}: no construction (${mode})`);
    primitiveCase(cases, `diff-${String(n).padStart(4, "0")}`, publicKey, signature, message, {
      key: mode === "small-a" || mode === "noncanonical-a" ? "forged" : `differential-${n}+T${jA}`,
      position: "verify",
      signature: `${mode}/r-torsion-${jR}`,
    });
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

function caseFile(family, cases, extraProvenance) {
  return {
    cases,
    family,
    format: FORMAT_CASES,
    provenance: { generator: GENERATOR_PATH, private_material_tracked: false, verdict_source: "pure-bigint-reference", ...extraProvenance },
  };
}

// Greedy split so every file stays inside FILE_BUDGET; deterministic names.
function emit(files, family, stem, cases, extraProvenance = {}) {
  const chunks = [];
  let current = [];
  const fits = (list) => {
    const doc = caseFile(family, list, extraProvenance);
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
    files.push({ path: `cases/${family}/${name}`, family, cases: chunk.length, doc: caseFile(family, chunk, extraProvenance) });
  });
}

function profileDoc(ruleIds) {
  return {
    case_envelope: {
      common: "id, rule (the REQ id the vector isolates), surface, construction {key, position, signature}, optional note",
      primitive: "surface ed25519.verify_strict | ed25519.acceptable_public_key | ed25519.torsion_free; input {public_key, signature, message} base64url; expected {verdict}; the named key-only forgeries name their contract major in the rule id (REQ1 or REQ2) and carry raw_cofactorless: accept (the ungated cofactorless equation accepts the vector)",
      v1_shaped: "families grant-verify, envelope, boundary-anchor, key-transition, anchored-export, jwk, jcs-utf8: the v1/v2 corpus case object (id, surface, class, input, expected) plus rule and major; input and expected are exactly that surface's v1/v2 shapes",
      loopback: "local_loopback_http: grant, compact, decode_local, decode_standard, envelope_local, issuer, request, nonce, target_uri (the profile.json fields inlined per case)",
      role_attestation: "role_attestation: compact, decode, verify, attestor, subject, now (the profile.json fields inlined per case)",
      content_assertion: "content_assertion: class, compact, expected {decode, verify}, attestor, expected_context (the profile.json expected block)",
    },
    class_mapping: "v1-shaped cases: A-side and key-acceptance rejects are invalid_key; R, S and equation rejects are invalid_encoding; UTF-8 rejects are invalid_encoding; grants with a leading U+FEFF are invalid_algorithm (in alg) or invalid_claim (any other header value, payload value or member name)",
    families: ["anchored-export", "boundary-anchor", "ca1", "differential", "envelope", "grant-verify", "jcs-utf8", "jwk", "key-acceptance", "key-transition", "loopback", "primitive", "ra1", "taming"],
    format: "bounded-authority-protocol-strict-ed25519-conformance-profile",
    profile: PROFILE,
    requirement_ids: ruleIds,
    revision: REVISION,
    rule: [
      "verify_strict(message, signature, public_key): 32-byte key and 64-byte signature; A and R canonical (y < p, and no sign bit when x = 0); neither A nor R of small order; S < L; then the cofactorless equation encode([S]B - [k]A) == R byte for byte",
      "acceptable_public_key?(raw): 32 bytes, canonical, on the curve, not of small order",
      "torsion_free?(raw): acceptable_public_key?(raw) and [L]A == O; a host requirement at enrollment, trust install and deny-list comparison, never on the verify path",
    ],
    torsion_note: TORSION_NOTE,
    verdict_source: "pure BigInt arithmetic (strict decode, [8]P == O, cofactorless equation); no blocklist and no backend; cross-checked at generation against node:crypto behind the S1 gate",
  };
}

function buildCorpus() {
  const files = [];
  emit(files, "primitive", "verify-strict", familyPrimitive());
  emit(files, "primitive", "key-only-forgeries", familyKeyOnly());
  // Both contract majors share one file per family; each case carries its `major` as data, so no
  // path names a major (ADR 0022 admits major tokens only on enumerated contract paths).
  const bothMajors = (family) => [...family(1), ...family(2)];
  emit(files, "grant-verify", "grant-verify", bothMajors(familyGrant));
  emit(files, "envelope", "envelope", bothMajors(familyEnvelope));
  emit(files, "boundary-anchor", "boundary-anchor", bothMajors(familyAnchor));
  emit(files, "key-transition", "key-transition", bothMajors(familyTransition));
  emit(files, "anchored-export", "anchored-export", bothMajors(familyExport));
  emit(files, "loopback", "holder", familyLoopback());
  emit(files, "ra1", "attestation", familyRoleAttestation());
  emit(files, "ca1", "assertion", familyContentAssertion());
  for (const [surface, cases] of Object.entries(familyJwk())) emit(files, "jwk", surface.slice(4).replaceAll("_", "-"), cases);
  emit(files, "taming", "speccheck", familyTaming(), { source: SPECCHECK_PROVENANCE });
  const jcs = familyJcs();
  emit(files, "jcs-utf8", "jcs-encode", jcs.encode);
  emit(files, "jcs-utf8", "request-digest", jcs.digest);
  emit(files, "jcs-utf8", "envelope", jcs.envelope);
  emit(files, "jcs-utf8", "invalid-sequences", jcs.invalid);
  emit(files, "jcs-utf8", "bom-preservation", jcs.bom);
  emit(files, "differential", "differential", familyDifferential());
  const ka = familyKeyAcceptance();
  emit(files, "key-acceptance", "acceptable-public-key", ka.acceptable);
  emit(files, "key-acceptance", "torsion-free", ka.torsion);

  if (disagreements.length > 0) {
    fail(`cross-check FAILED: ${disagreements.length} disagreement(s) between the BigInt reference and the cross-check:\n  ${disagreements.slice(0, 20).join("\n  ")}`);
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
    const text = `${canonical(doc)}\n`;
    const bytes = Buffer.from(text, "utf8");
    if (bytes.length > LIMITS.json_bytes) fail(`${path}: json_bytes bound`);
    const { nodes, depth } = jsonStats(doc);
    if (nodes > LIMITS.total_nodes || depth > LIMITS.depth) fail(`${path}: total_nodes/depth bound (${nodes}/${depth})`);
    out.set(path, bytes);
  };
  put("profile.json", profileDoc([...ruleIds].sort()));
  put("revision.json", { format: FORMAT_REVISION, generated_from: REVISION_NOTE, revision: REVISION });
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
  return { out, families };
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
  const started = Date.now();
  const { out, families } = buildCorpus();
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
  console.log(`build_strict_ed25519: ${ARGS.mode === "verify" ? "verify ok" : "wrote"} ${ARGS.out}`);
  console.log(`  node ${process.version}; files=${out.size}; total_cases=${total}; index sha256=${indexSha}`);
  console.log(`  families ${JSON.stringify(families)}`);
  console.log(
    `  cross-check: signatures=${stats.signaturesChecked} gate-passing=${stats.gatePassing} node-verify-calls=${stats.nodeVerifyCalls} ` +
      `keys=${stats.keysChecked} torsion=${stats.torsionChecked} honest-keys-vs-node=${stats.honestKeysChecked} disagreements=${disagreements.length}`,
  );
  console.log(`  key-only forgeries: ${keyOnlyStats.vectors} vectors; node:crypto raw backend accepts ${keyOnlyStats.rawNodeAccepts}`);
  console.log(`  ungated node:crypto accepts ${stats.ungatedNodeAcceptsRejected} signature(s) the strict rule rejects (forgeries this Node accepts without the gate)`);
  console.log(`  ${((Date.now() - started) / 1000).toFixed(1)}s`);
}

main();
