#!/usr/bin/env node

import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
} from "node:crypto";
import {readFile, readdir} from "node:fs/promises";
import {extname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(scriptPath, "../..");
const vectorsDir = join(root, "priv/conformance/v1/vectors");
const argumentsByName = new Map();
const missing = Symbol("missing");
const requiredDiscoveryRoots = [
  "priv/conformance/v1/vectors",
  "priv/conformance/v1/schemas",
  "conformance",
  "test",
];

for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  const value = process.argv[index + 1];
  if (!name?.startsWith("--") || value === undefined) fail("invalid arguments");
  argumentsByName.set(name, value);
}

const fixturePath = resolve(argumentsByName.get("--fixture") ?? join(vectorsDir, "grant-holder-proof.json"));
const manifestPath = resolve(argumentsByName.get("--manifest") ?? join(vectorsDir, "manifest.json"));

try {
  const fixture = await readJson(fixturePath);
  const manifest = await readJson(manifestPath);
  verifyFixture(fixture);
  await verifyManifest(manifest);
  process.stdout.write(
    `bap03 independent verification: ok\n` +
      `vectors=${manifest.vectors.length} public_key_fingerprints=` +
      `${manifest.canonical_public_key_fingerprints.length} tamper_cases=` +
      `${Object.keys(fixture.expected.tamper_verdicts).length}\n`,
  );
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}

function verifyFixture(fixture) {
  assertEqual(fixture.format, "bounded-authority-protocol-v1-grant-holder-proof", "fixture format");
  assertEqual(fixture.provenance.private_material_tracked, false, "private-material declaration");
  assertEqual(fixture.expected.verdict, "valid", "expected verdict");

  const issuerJwk = exactPublicJwk(fixture.public_keys.issuer.jwk);
  const holderJwk = exactPublicJwk(fixture.public_keys.holder.jwk);
  const issuerThumbprint = jwkThumbprint(issuerJwk);
  const holderThumbprint = jwkThumbprint(holderJwk);

  verifyPublicKeyRecord(fixture.public_keys.issuer, issuerThumbprint);
  verifyPublicKeyRecord(fixture.public_keys.holder, holderThumbprint);
  const atomKeyProbe = new Set();
  discoverTextKeys(`%{x: "${fixture.public_keys.holder.jwk.x}"}`, atomKeyProbe);
  assertDeepEqual([...atomKeyProbe], [holderThumbprint], "Elixir atom-key census");

  const grant = verifyCompactRecord(fixture.grant, issuerJwk, "grant");
  const proof = verifyCompactRecord(fixture.proof, holderJwk, "proof");
  exactKeys(grant.header, ["alg", "kid", "typ"], "grant header");
  exactKeys(proof.header, ["alg", "jwk", "typ"], "proof header");
  assertDeepEqual(exactPublicJwk(proof.header.jwk), holderJwk, "proof public JWK");
  assertDeepEqual(grant.header, fixture.grant.header, "grant parsed header");
  assertDeepEqual(proof.header, fixture.proof.header, "proof parsed header");
  assertDeepEqual(grant.payload, fixture.grant.payload, "grant parsed payload");
  assertDeepEqual(proof.payload, fixture.proof.payload, "proof parsed payload");
  assertEqual(grant.header.alg, "EdDSA", "grant alg");
  assertEqual(grant.header.typ, "ba+cap", "grant typ");
  assertEqual(proof.header.alg, "EdDSA", "proof alg");
  assertEqual(proof.header.typ, "dpop+jwt", "proof typ");

  const expected = fixture.expected_context;
  const grantPayload = grant.payload;
  const proofPayload = proof.payload;
  exactKeys(
    grantPayload,
    ["aud", "cnf", "exp", "iat", "iss", "jti", "nbf", "operations", "v"],
    "grant payload",
  );
  exactKeys(
    proofPayload,
    ["ath", "ba_inv", "ba_op", "ba_req", "htm", "htu", "iat", "jti", "nonce", "v"],
    "proof payload",
  );
  assertEqual(grantPayload.v, 1, "grant version");
  assertEqual(proofPayload.v, 1, "proof version");
  assertEqual(grant.header.kid, expected.trusted_issuer.key_id, "issuer key id");
  assertEqual(issuerJwk.x, expected.trusted_issuer.public_key_base64url, "issuer public key");
  assertEqual(grantPayload.iss, expected.issuer, "issuer");
  assert(grantPayload.aud.includes(expected.audience), "audience");
  assert(grantPayload.iat < grantPayload.exp, "grant iat/exp coherence");
  assert(grantPayload.nbf < grantPayload.exp, "grant nbf/exp coherence");
  assert(grantPayload.iat <= expected.evaluation_time + expected.clock_skew, "grant iat time");
  assert(grantPayload.nbf <= expected.evaluation_time + expected.clock_skew, "grant nbf time");
  assert(grantPayload.exp > expected.evaluation_time - expected.clock_skew, "grant exp time");
  assertEqual(grantPayload.cnf.jkt, holderThumbprint, "holder thumbprint");

  const grantHash = sha256(Buffer.from(fixture.grant.compact, "ascii"));
  const ath = encodeBase64Url(grantHash);
  assertEqual(fixture.grant.ath, ath, "stored ath");
  assertEqual(proofPayload.ath, ath, "proof ath");
  assertEqual(proofPayload.htm, expected.method, "method");
  assertEqual(proofPayload.htu, expected.target_uri, "target URI");
  assertNormalizedHttps(proofPayload.htu);
  assertEqual(proofPayload.ba_inv, expected.invocation_id, "invocation");
  assertEqual(proofPayload.ba_op, expected.operation, "operation");
  assert(
    proofPayload.iat >=
      expected.evaluation_time - expected.proof_max_age - expected.clock_skew,
    "proof minimum time",
  );
  assert(proofPayload.iat <= expected.evaluation_time + expected.clock_skew, "proof maximum time");
  assertEqual(proofPayload.nonce, expected.nonce.required, "nonce");

  validateTyped(fixture.request.typed_cast_arguments);
  assertDeepEqual(
    eraseTyped(fixture.request.typed_cast_arguments),
    expected.cast_arguments,
    "typed request argument projection",
  );
  const requestJcs = canonicalize([expected.operation, fixture.request.typed_cast_arguments]);
  const requestPreimage = Buffer.concat([
    Buffer.from("BAP1-REQUEST\0", "ascii"),
    Buffer.from(requestJcs, "utf8"),
  ]);
  const requestHash = sha256(requestPreimage);
  const requestDigest = encodeBase64Url(requestHash);
  assertEqual(fixture.request.jcs, requestJcs, "request JCS");
  assertEqual(
    fixture.request.preimage_base64url,
    encodeBase64Url(requestPreimage),
    "request preimage",
  );
  assertEqual(fixture.request.ba_req, requestDigest, "stored ba_req");
  assertEqual(proofPayload.ba_req, requestDigest, "proof ba_req");

  const operations = grantPayload.operations.filter(({name}) => name === expected.operation);
  assertEqual(operations.length, 1, "unique requested operation");
  for (const selector of operations[0].selectors) {
    assert(selectorAllows(selector, expected.cast_arguments), "selector");
  }

  const grantFacts = {
    version: 1,
    issuer: grantPayload.iss,
    grant_id: grantPayload.jti,
    issuer_key_fingerprint_base64url: issuerThumbprint,
    holder_thumbprint_base64url: holderThumbprint,
    matched_audience: expected.audience,
    issued_at: grantPayload.iat,
    not_before: grantPayload.nbf,
    expires_at: grantPayload.exp,
    authorization: "not_evaluated",
  };
  const envelopeFacts = {
    ...grantFacts,
    proof_id: proofPayload.jti,
    invocation_id: proofPayload.ba_inv,
    operation: proofPayload.ba_op,
    target_uri: proofPayload.htu,
    grant_hash_base64url: encodeBase64Url(grantHash),
    request_hash_base64url: encodeBase64Url(requestHash),
    proof_issued_at: proofPayload.iat,
  };
  assertDeepEqual(fixture.expected.grant_facts, grantFacts, "grant facts");
  assertDeepEqual(fixture.expected.envelope_facts, envelopeFacts, "envelope facts");

  verifyMemberOrderVariant(fixture, issuerJwk, holderJwk);
  verifyAuxiliaryCases(fixture, issuerJwk, holderJwk, holderThumbprint, requestDigest);
  verifyOfficialVectors(fixture.official_vectors, issuerJwk);
  verifyTamperMatrix(fixture, issuerJwk, holderJwk, requestDigest);
}

function verifyAuxiliaryCases(
  fixture,
  issuerJwk,
  holderJwk,
  holderThumbprint,
  requestDigest,
) {
  const nonceAbsent = verifyCompactRecord(
    fixture.positive_cases.nonce_absent.proof,
    holderJwk,
    "nonce-absent proof",
  );
  exactKeys(
    nonceAbsent.payload,
    ["ath", "ba_inv", "ba_op", "ba_req", "htm", "htu", "iat", "jti", "v"],
    "nonce-absent proof payload",
  );
  assert(!("nonce" in nonceAbsent.payload), "nonce-absent proof");
  assertEqual(nonceAbsent.payload.ba_req, requestDigest, "nonce-absent request digest");
  assertEqual(
    fixture.positive_cases.nonce_absent.expected_verdict,
    "valid",
    "nonce-absent verdict",
  );

  const wrongRecord = fixture.negative_cases.wrong_holder.proof;
  const wrongProtected = JSON.parse(
    decodeBase64Url(wrongRecord.protected_segment).toString("utf8"),
  );
  const wrongJwk = exactPublicJwk(wrongProtected.jwk);
  const wrongHolder = verifyCompactRecord(wrongRecord, wrongJwk, "wrong-holder proof");
  assertDeepEqual(wrongHolder.header, wrongRecord.header, "wrong-holder parsed header");
  assertEqual(wrongHolder.payload.ba_req, requestDigest, "wrong-holder request digest");
  assert(
    !safeEqual(
      decodeBase64Url(jwkThumbprint(wrongJwk)),
      decodeBase64Url(holderThumbprint),
    ),
    "wrong-holder thumbprint mismatch",
  );
  assertEqual(
    fixture.negative_cases.wrong_holder.expected_verdict,
    "invalid",
    "wrong-holder verdict",
  );

  for (const [name, selectorCase] of Object.entries(
    fixture.negative_cases.selector_denied,
  )) {
    validateTyped(selectorCase.typed_cast_arguments);
    assertDeepEqual(
      eraseTyped(selectorCase.typed_cast_arguments),
      selectorCase.cast_arguments,
      `selector ${name} typed projection`,
    );
    const requestJcs = canonicalize([
      fixture.expected_context.operation,
      selectorCase.typed_cast_arguments,
    ]);
    assertEqual(requestJcs, selectorCase.request_jcs, `selector ${name} request JCS`);
    const requestHash = sha256(
      Buffer.concat([
        Buffer.from("BAP1-REQUEST\0", "ascii"),
        Buffer.from(requestJcs, "utf8"),
      ]),
    );
    const proof = verifyCompactRecord(
      selectorCase.proof,
      holderJwk,
      `selector ${name} proof`,
    );
    assertEqual(
      proof.payload.ba_req,
      encodeBase64Url(requestHash),
      `selector ${name} request digest`,
    );
    const operation = fixture.grant.payload.operations.find(
      ({name: operationName}) => operationName === fixture.expected_context.operation,
    );
    assert(
      operation.selectors.some(
        (selector) => !selectorAllows(selector, selectorCase.cast_arguments),
      ),
      `selector ${name} denial`,
    );
    assertEqual(selectorCase.expected_verdict, "invalid", `selector ${name} verdict`);
  }

  for (const timeCase of fixture.grant_time_cases) {
    const record = verifyCompactRecord(timeCase.grant, issuerJwk, `grant time ${timeCase.name}`);
    const payload = record.payload;
    const expected = fixture.expected_context;
    const valid =
      payload.iat < payload.exp &&
      payload.nbf < payload.exp &&
      payload.iat <= expected.evaluation_time + expected.clock_skew &&
      payload.nbf <= expected.evaluation_time + expected.clock_skew &&
      payload.exp > expected.evaluation_time - expected.clock_skew;
    assertEqual(valid ? "valid" : "invalid", timeCase.expected_verdict, timeCase.name);
  }
}

function verifyCompactRecord(record, jwk, label) {
  const protectedBytes = decodeBase64Url(record.protected_segment);
  const payloadBytes = decodeBase64Url(record.payload_segment);
  const signature = decodeBase64Url(record.signature_base64url);
  assertEqual(signature.length, 64, `${label} signature length`);
  assertEqual(protectedBytes.toString("utf8"), record.protected_json, `${label} protected bytes`);
  assertEqual(payloadBytes.toString("utf8"), record.payload_json, `${label} payload bytes`);
  assertEqual(encodeBase64Url(protectedBytes), record.protected_segment, `${label} protected segment`);
  assertEqual(encodeBase64Url(payloadBytes), record.payload_segment, `${label} payload segment`);
  assertEqual(
    `${record.protected_segment}.${record.payload_segment}`,
    record.signing_input,
    `${label} standard JWS input`,
  );
  assert(!record.signing_input.startsWith("BAP1-"), `${label} has no private prefix`);
  assertEqual(
    `${record.signing_input}.${record.signature_base64url}`,
    record.compact,
    `${label} compact`,
  );
  assert(
    verifyEd25519(jwk, Buffer.from(record.signing_input, "ascii"), signature),
    `${label} signature`,
  );
  return {
    header: JSON.parse(record.protected_json),
    payload: JSON.parse(record.payload_json),
  };
}

function verifyPublicKeyRecord(record, expectedThumbprint) {
  assertEqual(record.raw_base64url, record.jwk.x, "raw public key");
  assertEqual(record.thumbprint_preimage, jwkThumbprintPreimage(record.jwk), "thumbprint preimage");
  assertEqual(record.thumbprint_base64url, expectedThumbprint, "thumbprint");
}

function verifyOfficialVectors(vectors, issuerJwk) {
  const jose = vectors.rfc8037_appendix_a;
  assertDeepEqual(exactPublicJwk(jose.jwk), issuerJwk, "RFC 8037 public key");
  assertEqual(jose.thumbprint_preimage, jwkThumbprintPreimage(jose.jwk), "RFC 8037 preimage");
  assertEqual(jose.thumbprint_base64url, jwkThumbprint(jose.jwk), "RFC 8037 thumbprint");
  assert(
    verifyEd25519(
      jose.jwk,
      Buffer.from(jose.signing_input, "ascii"),
      decodeBase64Url(jose.signature_base64url),
    ),
    "RFC 8037 signature",
  );

  const ed25519 = vectors.rfc8032_test_1;
  const rfcJwk = {crv: "Ed25519", kty: "OKP", x: ed25519.public_key_base64url};
  assert(
    verifyEd25519(
      rfcJwk,
      decodeBase64Url(ed25519.message_base64url),
      decodeBase64Url(ed25519.signature_base64url),
    ),
    "RFC 8032 signature",
  );
}

function verifyMemberOrderVariant(fixture, issuerJwk, holderJwk) {
  const variant = fixture.received_member_order_variant;
  assertEqual(variant.expected_verdict, "valid", "member-order variant verdict");
  const grant = verifyCompactRecord(variant.grant, issuerJwk, "member-order grant");
  const proof = verifyCompactRecord(variant.proof, holderJwk, "member-order proof");

  assertDeepEqual(grant.header, fixture.grant.header, "member-order grant header semantics");
  assertDeepEqual(grant.payload, fixture.grant.payload, "member-order grant payload semantics");
  assertDeepEqual(proof.header, fixture.proof.header, "member-order proof header semantics");

  const expectedProofPayload = {
    ...fixture.proof.payload,
    ath: encodeBase64Url(sha256(Buffer.from(variant.grant.compact, "ascii"))),
  };
  assertDeepEqual(proof.payload, expectedProofPayload, "member-order proof payload semantics");
  assertEqual(proof.payload.ba_req, fixture.request.ba_req, "member-order request digest");
}

function verifyTamperMatrix(fixture, issuerJwk, holderJwk, requestDigest) {
  const expected = fixture.expected.tamper_verdicts;
  exactKeys(
    expected,
    [
      "grant_payload_byte_flip",
      "grant_protected_byte_flip",
      "grant_signature_byte_flip",
      "proof_payload_byte_flip",
      "proof_protected_byte_flip",
      "proof_signature_byte_flip",
      "request_operation_drift",
    ],
    "tamper verdicts",
  );
  for (const verdict of Object.values(expected)) assertEqual(verdict, "invalid", "tamper verdict");

  assert(
    !verifyEd25519(
      issuerJwk,
      flipAscii(fixture.grant.signing_input, 0),
      decodeBase64Url(fixture.grant.signature_base64url),
    ),
    "grant protected tamper",
  );
  assert(
    !verifyEd25519(
      issuerJwk,
      flipAscii(fixture.grant.signing_input, fixture.grant.protected_segment.length + 1),
      decodeBase64Url(fixture.grant.signature_base64url),
    ),
    "grant payload tamper",
  );
  assert(
    !verifyEd25519(
      issuerJwk,
      Buffer.from(fixture.grant.signing_input, "ascii"),
      flipByte(decodeBase64Url(fixture.grant.signature_base64url), 32),
    ),
    "grant signature tamper",
  );
  assert(
    !verifyEd25519(
      holderJwk,
      flipAscii(fixture.proof.signing_input, 0),
      decodeBase64Url(fixture.proof.signature_base64url),
    ),
    "proof protected tamper",
  );
  assert(
    !verifyEd25519(
      holderJwk,
      flipAscii(fixture.proof.signing_input, fixture.proof.protected_segment.length + 1),
      decodeBase64Url(fixture.proof.signature_base64url),
    ),
    "proof payload tamper",
  );
  assert(
    !verifyEd25519(
      holderJwk,
      Buffer.from(fixture.proof.signing_input, "ascii"),
      flipByte(decodeBase64Url(fixture.proof.signature_base64url), 32),
    ),
    "proof signature tamper",
  );
  const driftedPreimage = Buffer.concat([
    Buffer.from("BAP1-REQUEST\0", "ascii"),
    Buffer.from(
      canonicalize(["write_record", fixture.request.typed_cast_arguments]),
      "utf8",
    ),
  ]);
  assert(
    !safeEqual(sha256(driftedPreimage), decodeBase64Url(requestDigest)),
    "request operation tamper",
  );
}

async function verifyManifest(manifest) {
  assertEqual(manifest.format, "bounded-authority-protocol-v1-vector-manifest", "manifest format");
  const vectors = [...manifest.vectors].sort();
  assertDeepEqual(vectors, ["grant-holder-proof.json"], "manifest vectors");
  assertDeepEqual(
    [...manifest.discovery_roots].sort(),
    [...requiredDiscoveryRoots].sort(),
    "manifest discovery roots",
  );

  const discovered = new Set();
  for (const relativeRoot of requiredDiscoveryRoots) {
    const path = resolve(root, relativeRoot);
    assert(path === root || path.startsWith(`${root}/`), "discovery root escape");
    await discoverPublicKeys(path, discovered);
  }

  const listed = [...manifest.canonical_public_key_fingerprints].sort();
  const actual = [...discovered].sort();
  assertEqual(new Set(listed).size, listed.length, "duplicate manifest fingerprint");
  assertDeepEqual(listed, actual, "manifest public-key fingerprint set");
}

async function discoverPublicKeys(path, fingerprints) {
  let entries;
  try {
    entries = await readdir(path, {withFileTypes: true});
  } catch {
    const bytes = await readFile(path);
    if (path === manifestPath || path.endsWith("/manifest.json")) return;
    if (extname(path) === ".json") {
      discoverJsonKeys(JSON.parse(bytes.toString("utf8")), fingerprints);
    } else {
      discoverTextKeys(bytes.toString("utf8"), fingerprints);
    }
    return;
  }

  for (const entry of entries) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) await discoverPublicKeys(child, fingerprints);
    else if (entry.isFile()) await discoverPublicKeys(child, fingerprints);
  }
}

function discoverJsonKeys(value, fingerprints) {
  if (Array.isArray(value)) {
    for (const item of value) discoverJsonKeys(item, fingerprints);
    return;
  }
  if (!value || typeof value !== "object") return;

  if (value.kty === "OKP" && value.crv === "Ed25519" && typeof value.x === "string") {
    fingerprints.add(jwkThumbprint(exactPublicJwk(value)));
  }
  for (const [key, child] of Object.entries(value)) {
    if (
      ["public_key_base64url", "raw_base64url"].includes(key) &&
      typeof child === "string"
    ) {
      fingerprints.add(jwkThumbprint(exactPublicJwk({crv: "Ed25519", kty: "OKP", x: child})));
    }
    discoverJsonKeys(child, fingerprints);
  }
}

function discoverTextKeys(text, fingerprints) {
  const pattern =
    /(?:public_key_base64url|raw_base64url|["']x["']|\bx)\s*(?::|=>)\s*["']([A-Za-z0-9_-]{43})["']/g;
  for (const match of text.matchAll(pattern)) {
    try {
      fingerprints.add(
        jwkThumbprint(exactPublicJwk({crv: "Ed25519", kty: "OKP", x: match[1]})),
      );
    } catch {
      // Malformed-key deny fixtures are reachable but are not public keys.
    }
  }
}

function validateTyped(value) {
  assert(Array.isArray(value), "typed value array");
  assert(typeof value[0] === "string", "typed value tag");

  switch (value[0]) {
    case "null":
      assertEqual(value.length, 1, "typed null shape");
      return;
    case "boolean":
      assertEqual(value.length, 2, "typed boolean shape");
      assert(typeof value[1] === "boolean", "typed boolean value");
      return;
    case "integer":
      assertEqual(value.length, 2, "typed integer shape");
      assert(Number.isSafeInteger(value[1]), "typed integer value");
      return;
    case "float":
      assertEqual(value.length, 2, "typed float shape");
      assert(Number.isFinite(value[1]), "typed float value");
      return;
    case "string":
      assertEqual(value.length, 2, "typed string shape");
      assert(typeof value[1] === "string", "typed string value");
      return;
    case "array":
      assertEqual(value.length, 2, "typed array shape");
      assert(Array.isArray(value[1]), "typed array value");
      for (const child of value[1]) validateTyped(child);
      return;
    case "object":
      assertEqual(value.length, 2, "typed object shape");
      assert(value[1] && typeof value[1] === "object" && !Array.isArray(value[1]), "typed object value");
      for (const child of Object.values(value[1])) validateTyped(child);
      return;
    default:
      throw new Error("typed value tag invalid");
  }
}

function eraseTyped(value) {
  switch (value[0]) {
    case "null":
      return null;
    case "boolean":
    case "integer":
    case "float":
    case "string":
      return value[1];
    case "array":
      return value[1].map(eraseTyped);
    case "object":
      return Object.fromEntries(
        Object.entries(value[1]).map(([key, child]) => [key, eraseTyped(child)]),
      );
    default:
      throw new Error("typed value tag invalid");
  }
}

function selectorAllows(selector, input) {
  exactKeys(
    selector,
    selector.kind === "all"
      ? ["kind"]
      : selector.kind === "equals"
        ? ["kind", "path", "value"]
        : ["kind", "path", "values"],
    "selector",
  );
  if (selector.kind === "all") return true;
  const value = objectPath(input, selector.path);
  if (value === missing) return false;
  if (selector.kind === "equals") return semanticEqual(value, selector.value);
  if (selector.kind === "one_of") {
    return selector.values.some((candidate) => semanticEqual(value, candidate));
  }
  return false;
}

function objectPath(value, path) {
  for (const name of path) {
    if (!isPlainObject(value) || !Object.hasOwn(value, name)) return missing;
    value = value[name];
  }
  return value;
}

function semanticEqual(left, right) {
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => semanticEqual(value, right[index]))
    );
  }
  if (isPlainObject(left) || isPlainObject(right)) {
    if (!isPlainObject(left) || !isPlainObject(right)) return false;
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    return (
      JSON.stringify(leftKeys) === JSON.stringify(rightKeys) &&
      leftKeys.every((key) => semanticEqual(left[key], right[key]))
    );
  }
  return Object.is(left, right);
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number"
  ) {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (!isPlainObject(value)) throw new Error("non-JSON value");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

function exactPublicJwk(value) {
  exactKeys(value, ["crv", "kty", "x"], "public JWK");
  assertEqual(value.crv, "Ed25519", "JWK curve");
  assertEqual(value.kty, "OKP", "JWK type");
  assertEqual(decodeBase64Url(value.x).length, 32, "JWK key length");
  return {crv: value.crv, kty: value.kty, x: value.x};
}

function jwkThumbprintPreimage(jwk) {
  return canonicalize({crv: jwk.crv, kty: jwk.kty, x: jwk.x});
}

function jwkThumbprint(jwk) {
  return encodeBase64Url(sha256(Buffer.from(jwkThumbprintPreimage(jwk), "utf8")));
}

function verifyEd25519(jwk, message, signature) {
  if (signature.length !== 64) return false;
  return verify(
    null,
    message,
    createPublicKey({key: exactPublicJwk(jwk), format: "jwk"}),
    signature,
  );
}

function assertNormalizedHttps(uri) {
  assert(/^[\x20-\x7E]+$/.test(uri), "URI ASCII");
  const parsed = new URL(uri);
  assertEqual(parsed.protocol, "https:", "URI scheme");
  assert(parsed.host.length > 0, "URI host");
  assertEqual(parsed.username, "", "URI username");
  assertEqual(parsed.password, "", "URI password");
  assertEqual(parsed.search, "", "URI query");
  assertEqual(parsed.hash, "", "URI fragment");
  assertEqual(parsed.href, uri, "URI normalized");
}

function decodeBase64Url(value) {
  assert(typeof value === "string", "base64url type");
  assert(/^[A-Za-z0-9_-]*$/.test(value), "base64url alphabet");
  assert(value.length % 4 !== 1, "base64url length");
  const decoded = Buffer.from(value, "base64url");
  assertEqual(encodeBase64Url(decoded), value, "canonical base64url");
  return decoded;
}

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function sha256(value) {
  return createHash("sha256").update(value).digest();
}

function safeEqual(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}

function flipAscii(value, index) {
  const bytes = Buffer.from(value, "ascii");
  return flipByte(bytes, index);
}

function flipByte(value, index) {
  const bytes = Buffer.from(value);
  bytes[index] ^= 0x01;
  return bytes;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected, label) {
  assert(isPlainObject(value), `${label} object`);
  assertDeepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} keys`);
}

function assertDeepEqual(actual, expected, label) {
  assertEqual(canonicalize(actual), canonicalize(expected), label);
}

function assertEqual(actual, expected, label) {
  if (!Object.is(actual, expected)) {
    throw new Error(`${label} mismatch`);
  }
}

function assert(condition, label) {
  if (!condition) throw new Error(`${label} failed`);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function fail(message) {
  process.stderr.write(`bap03 independent verification: invalid (${message})\n`);
  process.exit(1);
}
