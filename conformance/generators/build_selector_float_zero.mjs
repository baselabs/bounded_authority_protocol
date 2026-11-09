#!/usr/bin/env node
// Generator for the additive selector float-zero corpus `bap-selector-float-zero/1` (erratum 6).
//
// The rule (spec/bap-v1.md § 12, spec/bap-v2.md § 4, spec/bap-v3.md; errata registry entry 6):
//   - verification, every contract-major: grant decode rejects an `equals` value or `one_of`
//     member that holds a float-tagged number equal to zero at any depth (any sign, any
//     spelling); range bounds and inert `all` members are unchanged;
//   - producers, every contract-major: `grant_signing_input` refuses any float-tagged integral
//     selector value (equals, one_of, and the v2/v3 range bounds), because RFC 8785 writes an
//     integral float as integer text that decodes integer-tagged.
//
// Verdicts come from the rule text and each case's construction, not from any implementation.
// Values whose float tag matters travel as JSON text (`operations_json`, `cast_arguments_json`)
// that every runner decodes with its own tag-preserving BAP JSON decoder; a JSON number in a
// case file cannot carry `-0.0` or an integral float through every language's JSON library.
//
// Families:
//   grant-decode         decode_grant over hand-written (non-JCS) payload bytes; keyless
//   grant-signing-input  grant_signing_input; keyless, deterministic
//   envelope             check_envelope controls; minted once with ephemeral in-memory keys
//                        (only public keys are recorded) and frozen thereafter
//
// Usage:
//   node conformance/generators/build_selector_float_zero.mjs --write    mint and write the corpus
//   node conformance/generators/build_selector_float_zero.mjs --verify   shipped corpus == rule
//
// --verify rebuilds both keyless families byte for byte, re-derives every envelope case except
// its signatures (verdict, grant payload, ath, ba_req, request context) and verifies each
// recorded signature under its recorded public key, then checks the index, profile and revision.

import { createHash, generateKeyPairSync, sign, verify, createPublicKey } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const corpusDir = join(root, "priv/conformance/selector-float-zero");

const PROFILE = "bap-selector-float-zero/1";
const REVISION = 1;
const FORMAT = "bounded-authority-protocol-selector-float-zero-conformance";

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "https://resource.example.test";
const TARGET = "https://resource.example.test/invoke";
const INVOCATION = "550e8400-e29b-41d4-a716-446655440000";
const OPERATION = "transfer";
const HOLDER_THUMBPRINT_FIXED = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"; // 32 × 0x07
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const RULE_VERIFY = { 1: "REQ1-SELECTOR-float-zero", 2: "REQ2-SELECTOR-float-zero", 3: "REQ3-SELECTOR-float-zero" };
const RULE_PRODUCE = {
  1: "REQ1-SIGNING-integral-float-selector",
  2: "REQ2-SIGNING-integral-float-selector",
  3: "REQ3-SIGNING-integral-float-selector",
};

// Every spelling decodes to a float-tagged zero: a fraction or an exponent marks a float
// lexeme, and 1e-400 underflows to zero (the sign survives in some decoders and not others,
// which is exactly why the rule is keyed on the decoded value).
const ZERO_SPELLINGS = ["0.0", "-0.0", "0e0", "-0e0", "-0E0", "-0e-5", "0.000", "1e-400", "-1e-400"];

// ---- tagged values and serialization ---------------------------------------------------------

const int = (n) => ({ t: "integer", v: n });
const flt = (lexeme) => ({ t: "float", lexeme, v: Number(lexeme) });
const arr = (...items) => ({ t: "array", v: items });
const obj = (members) => ({ t: "object", v: members });

// JSON text that keeps each float's lexeme (so a decoder sees a float, with its sign).
function lexemeJson(value) {
  switch (value.t) {
    case "integer":
      return String(value.v);
    case "float":
      return value.lexeme;
    case "array":
      return "[" + value.v.map(lexemeJson).join(",") + "]";
    case "object":
      return "{" + value.v.map(([k, v]) => JSON.stringify(k) + ":" + lexemeJson(v)).join(",") + "}";
    default:
      throw new Error("unsupported tagged value");
  }
}

// RFC 8785 for plain JS values (strings, finite numbers, arrays, objects). JSON.stringify emits
// the ECMAScript Number::toString form RFC 8785 § 3.2.2.3 requires, including -0 as "0".
function jcs(value) {
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
  }
  if (typeof value === "number" && !Number.isFinite(value)) throw new Error("non-finite");
  return JSON.stringify(value);
}

// The request-digest projection of spec/bap-v1.md § 14.
function typed(value) {
  switch (value.t) {
    case "integer":
      return ["integer", value.v];
    case "float":
      return ["float", value.v];
    case "array":
      return ["array", value.v.map(typed)];
    case "object":
      return ["object", Object.fromEntries(value.v.map(([k, v]) => [k, typed(v)]))];
    default:
      throw new Error("unsupported tagged value");
  }
}

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest();
const utf8 = (text) => Buffer.from(text, "utf8");

// ---- case construction -----------------------------------------------------------------------

const alg = (major) => (major === 3 ? "ES256" : "EdDSA");
const grantProtected = (major) => b64(utf8(jcs({ alg: alg(major), kid: "issuer", typ: "ba+cap" })));

// A grant payload written by hand: canonical member order, but each selector is spliced in as
// lexeme-preserving text, which is exactly the non-JCS byte form a verifier must still accept.
function grantPayloadText(major, selectorText, jkt) {
  return (
    `{"aud":[${JSON.stringify(AUDIENCE)}],"cnf":{"jkt":${JSON.stringify(jkt)}},"exp":2000,"iat":1000,` +
    `"iss":${JSON.stringify(ISSUER)},"jti":"urn:example:grant:float-zero","nbf":1000,` +
    `"operations":[{"name":${JSON.stringify(OPERATION)},"selectors":[${selectorText}]}],"v":${major}}`
  );
}

const selectorText = (kind, valueText) =>
  kind === "one_of"
    ? `{"kind":"one_of","path":["x"],"values":${valueText}}`
    : `{"kind":${JSON.stringify(kind)},"path":["x"],"value":${valueText}}`;

// A fixed, structurally valid 64-byte signature segment: decode does not verify signatures.
const DECODE_SIGNATURE = b64(Buffer.alloc(64, 0x11));

function decodeCases(major) {
  const cases = [];
  const add = (id, construction, sel, verdict) => {
    const payload = b64(utf8(grantPayloadText(major, sel, HOLDER_THUMBPRINT_FIXED)));
    cases.push({
      class: verdict === "valid" ? "valid" : "invalid_selector",
      construction,
      expected: verdict === "valid" ? { key_id: "issuer", verdict: "valid" } : { verdict: "invalid" },
      id: `decode-v${major}-${id}`,
      input: { compact: `${grantProtected(major)}.${payload}.${DECODE_SIGNATURE}` },
      major,
      rule: RULE_VERIFY[major],
      surface: "decode_grant",
    });
  };

  ZERO_SPELLINGS.forEach((z, i) =>
    add(`equals-zero-${i + 1}`, `equals value ${z}`, selectorText("equals", z), "invalid"),
  );
  add("equals-array-zero", "equals value [1,-0.0]", selectorText("equals", "[1,-0.0]"), "invalid");
  add("equals-object-zero", 'equals value {"a":{"b":0.0}}', selectorText("equals", '{"a":{"b":0.0}}'), "invalid");
  add("one-of-member-zero", "one_of values [1,-0.0]", selectorText("one_of", "[1,-0.0]"), "invalid");
  add("one-of-nested-zero", "one_of values [[0e0]]", selectorText("one_of", "[[0e0]]"), "invalid");
  add("one-of-object-zero", 'one_of values [{"a":-0e-5}]', selectorText("one_of", '[{"a":-0e-5}]'), "invalid");

  add("equals-integer-zero", "equals value 0 (integer)", selectorText("equals", "0"), "valid");
  add("equals-integer-minus-zero", "equals value -0 (integer)", selectorText("equals", "-0"), "valid");
  add("equals-half", "equals value 0.5", selectorText("equals", "0.5"), "valid");
  add("equals-integral-float", "equals value 10.0 (decoders accept a non-zero integral float)", selectorText("equals", "10.0"), "valid");
  add("equals-exponent-integral", "equals value 1e1", selectorText("equals", "1e1"), "valid");
  add("equals-array-control", "equals value [0,1.5]", selectorText("equals", "[0,1.5]"), "valid");
  add("one-of-control", "one_of values [0,10.0,-2.25]", selectorText("one_of", "[0,10.0,-2.25]"), "valid");
  add("all-inert-zero", "all with inert value -0.0", '{"kind":"all","path":["x"],"value":-0.0}', "valid");
  if (major !== 1) {
    for (const kind of ["lte", "gte"]) {
      for (const [n, z] of [["0.0", "plus"], ["-0.0", "minus"], ["-0e0", "exponent"]].map(([a, b]) => [b, a])) {
        add(`${kind}-bound-zero-${n}`, `${kind} bound ${z} (ranges compare numerically)`, selectorText(kind, z), "valid");
      }
    }
  }
  return cases;
}

const grantInputBase = () => ({
  audiences: [AUDIENCE],
  expires_at: 2000,
  grant_id: "urn:example:grant:float-zero",
  holder_thumbprint: HOLDER_THUMBPRINT_FIXED,
  issued_at: 1000,
  issuer: ISSUER,
  key_id: "issuer",
  not_before: 1000,
});

// Plain JS view of a tagged value for the JCS payload (only producer-valid values reach here).
function plain(value) {
  switch (value.t) {
    case "integer":
    case "float":
      return value.v;
    case "array":
      return value.v.map(plain);
    case "object":
      return Object.fromEntries(value.v.map(([k, v]) => [k, plain(v)]));
    default:
      throw new Error("unsupported tagged value");
  }
}

function signingInputCases(major) {
  const cases = [];
  const add = (id, construction, selector, verdict) => {
    const operations = [{ name: OPERATION, selectors: [selector] }];
    const operationsJson =
      "[{" +
      `"name":${JSON.stringify(OPERATION)},"selectors":[` +
      (selector.kind === "one_of"
        ? `{"kind":"one_of","path":["x"],"values":${lexemeJson(arr(...selector.values))}}`
        : `{"kind":${JSON.stringify(selector.kind)},"path":["x"],"value":${lexemeJson(selector.value)}}`) +
      "]}]";
    let expected = { verdict: "invalid" };
    if (verdict === "valid") {
      const sel =
        selector.kind === "one_of"
          ? { kind: "one_of", path: ["x"], values: selector.values.map(plain) }
          : { kind: selector.kind, path: ["x"], value: plain(selector.value) };
      const payload = jcs({
        aud: [AUDIENCE],
        cnf: { jkt: HOLDER_THUMBPRINT_FIXED },
        exp: 2000,
        iat: 1000,
        iss: ISSUER,
        jti: "urn:example:grant:float-zero",
        nbf: 1000,
        operations: operations.map(() => ({ name: OPERATION, selectors: [sel] })),
        v: major,
      });
      const protectedSegment = grantProtected(major);
      const payloadSegment = b64(utf8(payload));
      expected = {
        message: `${protectedSegment}.${payloadSegment}`,
        payload_segment: payloadSegment,
        protected_segment: protectedSegment,
        verdict: "valid",
      };
    }
    cases.push({
      class: verdict === "valid" ? "valid" : "invalid_selector",
      construction,
      expected,
      id: `signing-input-v${major}-${id}`,
      input: { ...grantInputBase(), operations_json: operationsJson },
      major,
      rule: RULE_PRODUCE[major],
      surface: "grant_signing_input",
    });
  };

  const eq = (value) => ({ kind: "equals", value });
  for (const [id, lexeme] of [["zero", "0.0"], ["minus-zero", "-0.0"], ["ten", "10.0"], ["minus-three", "-3.0"], ["two-pow-52", "4503599627370496.0"]]) {
    add(`equals-float-${id}`, `equals value float ${lexeme}`, eq(flt(lexeme)), "invalid");
  }
  add("equals-array-integral", "equals value [1, float 0.0]", eq(arr(int(1), flt("0.0"))), "invalid");
  add("equals-object-integral", "equals value {a: float 10.0}", eq(obj([["a", flt("10.0")]])), "invalid");
  add("one-of-integral", "one_of values [1, float -0.0]", { kind: "one_of", values: [int(1), flt("-0.0")] }, "invalid");
  add("equals-half", "equals value float 0.5", eq(flt("0.5")), "valid");
  add("equals-negative-fraction", "equals value float -2.25", eq(flt("-2.25")), "valid");
  add("equals-integer-zero", "equals value integer 0", eq(int(0)), "valid");
  add("one-of-control", "one_of values [integer 10, float 0.5]", { kind: "one_of", values: [int(10), flt("0.5")] }, "valid");
  if (major !== 1) {
    for (const kind of ["lte", "gte"]) {
      add(`${kind}-float-zero`, `${kind} bound float 0.0`, { kind, value: flt("0.0") }, "invalid");
      add(`${kind}-float-ten`, `${kind} bound float 10.0`, { kind, value: flt("10.0") }, "invalid");
      add(`${kind}-half`, `${kind} bound float 0.5`, { kind, value: flt("0.5") }, "valid");
    }
  }
  return cases;
}

// ---- envelope family (signed with ephemeral keys) --------------------------------------------

function keypair(major) {
  return major === 3
    ? generateKeyPairSync("ec", { namedCurve: "P-256" })
    : generateKeyPairSync("ed25519");
}

function publicJwk(major, publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  return major === 3 ? { crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y } : { crv: "Ed25519", kty: "OKP", x: jwk.x };
}

function rawPublicKey(major, jwk) {
  return major === 3
    ? Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")])
    : Buffer.from(jwk.x, "base64url");
}

const thumbprint = (jwk) => b64(sha256(utf8(jcs(jwk))));

function signMessage(major, privateKey, message) {
  if (major !== 3) return sign(null, utf8(message), privateKey);
  const raw = sign("sha256", utf8(message), { key: privateKey, dsaEncoding: "ieee-p1363" });
  const r = raw.subarray(0, 32);
  let s = BigInt("0x" + raw.subarray(32).toString("hex"));
  if (s > P256_N / 2n) s = P256_N - s;
  return Buffer.concat([r, Buffer.from(s.toString(16).padStart(64, "0"), "hex")]);
}

function verifyMessage(major, jwk, message, signature) {
  const key = createPublicKey({ key: { ...jwk }, format: "jwk" });
  return major === 3
    ? verify("sha256", utf8(message), { key, dsaEncoding: "ieee-p1363" }, signature)
    : verify(null, utf8(message), key, signature);
}

function requestDigest(major, args) {
  const prefix = Buffer.concat([utf8(`BAP${major}-REQUEST`), Buffer.from([0])]);
  return b64(sha256(Buffer.concat([prefix, utf8(jcs([OPERATION, typed(args)]))])));
}

function envelopeSpecs(major) {
  const specs = [];
  const x = (value) => obj([["x", value]]);
  for (const z of ["0.0", "-0.0", "-0e0"]) {
    for (const host of ["0.0", "-0.0"]) {
      specs.push({
        id: `equals-${z.replace(/^-/, "minus-").replace(".", "-")}-host-${host.replace(/^-/, "minus-").replace(".", "-")}`,
        construction: `equals value ${z}; host float ${host}`,
        selector: selectorText("equals", z),
        args: x(flt(host)),
        verdict: "invalid",
        rule: RULE_VERIFY[major],
      });
    }
  }
  for (const host of ["0.0", "-0.0"]) {
    specs.push({
      id: `integer-zero-host-float-${host.replace(/^-/, "minus-").replace(".", "-")}`,
      construction: `equals value integer 0; host float ${host} (tags never collapse)`,
      selector: selectorText("equals", "0"),
      args: x(flt(host)),
      verdict: "invalid",
      rule: "REQ1-SELECTOR-no-tag-collapse",
    });
  }
  specs.push({
    id: "integer-zero-host-integer-zero",
    construction: "equals value integer 0; host integer 0",
    selector: selectorText("equals", "0"),
    args: x(int(0)),
    verdict: "valid",
    rule: RULE_VERIFY[major],
  });
  if (major !== 1) {
    for (const [kind, bound, host] of [["lte", "0.0", "-0.0"], ["gte", "-0.0", "0.0"], ["lte", "-0e0", "0.0"], ["gte", "0.0", "-0.0"]]) {
      specs.push({
        id: `${kind}-${bound.replace(/^-/, "minus-").replace(".", "-")}-host-${host.replace(/^-/, "minus-").replace(".", "-")}`,
        construction: `${kind} bound ${bound}; host float ${host} (numeric comparison, −0.0 = 0.0)`,
        selector: selectorText(kind, bound),
        args: x(flt(host)),
        verdict: "valid",
        rule: `REQ${major}-SELECTOR-range-signed-zero`,
      });
    }
  }
  return specs;
}

const proofProtected = (major, jwk) => b64(utf8(jcs({ alg: alg(major), jwk, typ: "dpop+jwt" })));

function proofPayload(major, grant, args) {
  return b64(
    utf8(
      jcs({
        ath: b64(sha256(utf8(grant))),
        ba_inv: INVOCATION,
        ba_op: OPERATION,
        ba_req: requestDigest(major, args),
        htm: "POST",
        htu: TARGET,
        iat: 1100,
        jti: "urn:example:proof:float-zero",
        v: major,
      }),
    ),
  );
}

function expectedRequest(major, issuerJwk, args) {
  return {
    audience: AUDIENCE,
    cast_arguments_json: lexemeJson(args),
    clock_skew: 60,
    evaluation_time: 1200,
    invocation_id: INVOCATION,
    issuer: ISSUER,
    method: "POST",
    operation: OPERATION,
    proof_max_age: 300,
    target_uri: TARGET,
    trusted_issuer: { key_id: "issuer", public_key: b64(rawPublicKey(major, issuerJwk)) },
  };
}

function mintEnvelopeCases(major) {
  return envelopeSpecs(major).map((spec) => {
    const issuer = keypair(major);
    const holder = keypair(major);
    const issuerJwk = publicJwk(major, issuer.publicKey);
    const holderJwk = publicJwk(major, holder.publicKey);
    const grantMessage = `${grantProtected(major)}.${b64(utf8(grantPayloadText(major, spec.selector, thumbprint(holderJwk))))}`;
    const grant = `${grantMessage}.${b64(signMessage(major, issuer.privateKey, grantMessage))}`;
    const proofMessage = `${proofProtected(major, holderJwk)}.${proofPayload(major, grant, spec.args)}`;
    const proof = `${proofMessage}.${b64(signMessage(major, holder.privateKey, proofMessage))}`;
    return envelopeCase(major, spec, grant, proof, issuerJwk);
  });
}

function envelopeCase(major, spec, grant, proof, issuerJwk) {
  return {
    class: spec.verdict === "valid" ? "valid" : "invalid_selector",
    construction: spec.construction,
    expected: { verdict: spec.verdict },
    id: `envelope-v${major}-${spec.id}`,
    input: { expected: expectedRequest(major, issuerJwk, spec.args), grant, proof },
    major,
    rule: spec.rule,
    surface: "check_envelope",
  };
}

// Re-derive an envelope case from its recorded public material: every byte except the two
// signatures, which must verify under the recorded keys.
function verifyEnvelopeCase(major, spec, recorded) {
  const [gp, gpay, gsig] = recorded.input.grant.split(".");
  const [pp, ppay, psig] = recorded.input.proof.split(".");
  const holderJwk = JSON.parse(Buffer.from(pp, "base64url").toString("utf8")).jwk;
  const issuerRaw = Buffer.from(recorded.input.expected.trusted_issuer.public_key, "base64url");
  const issuerJwk =
    major === 3
      ? { crv: "P-256", kty: "EC", x: b64(issuerRaw.subarray(1, 33)), y: b64(issuerRaw.subarray(33)) }
      : { crv: "Ed25519", kty: "OKP", x: b64(issuerRaw) };
  const grantMessage = `${grantProtected(major)}.${b64(utf8(grantPayloadText(major, spec.selector, thumbprint(holderJwk))))}`;
  check(`${gp}.${gpay}` === grantMessage, `${recorded.id}: grant bytes`);
  check(verifyMessage(major, issuerJwk, grantMessage, Buffer.from(gsig, "base64url")), `${recorded.id}: grant signature`);
  const proofMessage = `${proofProtected(major, holderJwk)}.${proofPayload(major, recorded.input.grant, spec.args)}`;
  check(`${pp}.${ppay}` === proofMessage, `${recorded.id}: proof bytes`);
  check(verifyMessage(major, holderJwk, proofMessage, Buffer.from(psig, "base64url")), `${recorded.id}: proof signature`);
  const rebuilt = envelopeCase(major, spec, recorded.input.grant, recorded.input.proof, issuerJwk);
  check(serialize(rebuilt) === serialize(recorded), `${recorded.id}: case record`);
}

// ---- files -----------------------------------------------------------------------------------

const MAJORS = [1, 2, 3];
// One file per family and contract-major: the conformance loaders bound every case file by
// the profile's 64 KiB JSON maximum.
const FAMILIES = {
  "grant-decode": { build: decodeCases },
  "grant-signing-input": { build: signingInputCases },
  envelope: { build: mintEnvelopeCases },
};
const familyPath = (family, major) => `cases/${family}/major-${major}.json`;

const serialize = (value) => jcs(value);
const caseFile = (family, cases) =>
  serialize({ cases, family, format: `${FORMAT}-cases`, provenance: { private_material_tracked: false } });

const profileDoc = () =>
  serialize({
    case_envelope: {
      common: "id, rule, major, surface, class, construction, input, expected",
      typed_text:
        "operations_json and cast_arguments_json are JSON text; a runner decodes them with its own tag-preserving BAP JSON decoder (a fraction or exponent marks a float)",
    },
    class_mapping: "a case the rule rejects is invalid_selector; every other case is valid",
    families: Object.keys(FAMILIES),
    format: `${FORMAT}-profile`,
    profile: PROFILE,
    requirement_ids: [
      ...Object.values(RULE_VERIFY),
      ...Object.values(RULE_PRODUCE),
      "REQ1-SELECTOR-no-tag-collapse",
      "REQ2-SELECTOR-range-signed-zero",
      "REQ3-SELECTOR-range-signed-zero",
    ].sort(),
    revision: REVISION,
    rule: [
      "verification (contract-majors 1, 2 and 3): grant decode rejects an equals value or one_of member that holds a float-tagged number equal to zero at any depth, whatever its sign or spelling; range bounds and inert all members are unchanged",
      "producers (contract-majors 1, 2 and 3): grant_signing_input refuses any float-tagged integral selector value, including the contract-major 2 and 3 range bounds",
      "range bounds compare numerically: -0.0 = 0.0",
    ],
    verdict_source: "the rule text and each case's construction; envelope signatures come from ephemeral keys discarded at minting",
  });

const revisionDoc = () =>
  serialize({
    format: `${FORMAT}-corpus-revision`,
    generated_from: "conformance/generators/build_selector_float_zero.mjs",
    revision: REVISION,
  });

function indexDoc(files) {
  const entries = Object.entries(files)
    .map(([path, { bytes, cases }]) => ({ cases, path, sha256: sha256(bytes).toString("hex") }))
    .sort((a, b) => (a.path < b.path ? -1 : 1));
  const families = Object.fromEntries(
    Object.keys(FAMILIES).map((name) => [name, MAJORS.reduce((n, m) => n + files[familyPath(name, m)].cases, 0)]),
  );
  return serialize({
    families,
    files: entries,
    format: `${FORMAT}-corpus-index`,
    private_material_tracked: false,
    profile: PROFILE,
    revision: REVISION,
    total_cases: Object.values(families).reduce((a, b) => a + b, 0),
  });
}

// familyCases: { family: { major: [case, ...] } }
function assemble(familyCases) {
  const files = {};
  for (const name of Object.keys(FAMILIES)) {
    for (const major of MAJORS) {
      const cases = familyCases[name][major];
      files[familyPath(name, major)] = { bytes: utf8(caseFile(name, cases)), cases: cases.length };
    }
  }
  files["profile.json"] = { bytes: utf8(profileDoc()), cases: 0 };
  files["revision.json"] = { bytes: utf8(revisionDoc()), cases: 0 };
  return files;
}

function check(condition, label) {
  if (!condition) {
    console.error(`selector-float-zero: ${label}`);
    process.exit(1);
  }
}

function write() {
  const familyCases = Object.fromEntries(
    Object.entries(FAMILIES).map(([n, f]) => [n, Object.fromEntries(MAJORS.map((m) => [m, f.build(m)]))]),
  );
  const files = assemble(familyCases);
  for (const [path, { bytes }] of Object.entries(files)) {
    mkdirSync(dirname(join(corpusDir, path)), { recursive: true });
    writeFileSync(join(corpusDir, path), bytes);
  }
  writeFileSync(join(corpusDir, "index.json"), indexDoc(files));
  report(files);
}

function verifyShipped() {
  check(existsSync(join(corpusDir, "index.json")), "no shipped corpus");
  const read = (path) => readFileSync(join(corpusDir, path));
  const shippedEnvelope = {};
  for (const major of MAJORS) {
    const shipped = JSON.parse(read(familyPath("envelope", major))).cases;
    const specs = envelopeSpecs(major);
    check(shipped.length === specs.length, `envelope v${major} case count`);
    specs.forEach((spec, i) => verifyEnvelopeCase(major, spec, shipped[i]));
    shippedEnvelope[major] = shipped;
  }
  const rebuild = (build) => Object.fromEntries(MAJORS.map((m) => [m, build(m)]));
  const familyCases = {
    "grant-decode": rebuild(decodeCases),
    "grant-signing-input": rebuild(signingInputCases),
    envelope: shippedEnvelope,
  };
  const files = assemble(familyCases);
  for (const [path, { bytes }] of Object.entries(files)) {
    check(Buffer.compare(read(path), bytes) === 0, `${path} differs from the rule`);
  }
  check(read("index.json").toString("utf8") === indexDoc(files), "index.json differs");
  report(files);
}

function report(files) {
  const index = indexDoc(files);
  const total = JSON.parse(index).total_cases;
  console.log(`${PROFILE} revision ${REVISION}: ${total} cases; index sha256 ${sha256(utf8(index)).toString("hex")}`);
}

const mode = process.argv[2];
if (mode === "--write") write();
else if (mode === "--verify") verifyShipped();
else {
  console.error("usage: build_selector_float_zero.mjs --write | --verify");
  process.exit(2);
}
