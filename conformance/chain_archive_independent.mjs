import {
  createHash,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ARCHIVE_PREFIX = Buffer.from("BAP1-ARCHIVE\0EXPORT\0", "binary");
const ROW_PREFIX = Buffer.from("BAP1-CHAIN\0", "binary");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const importedPublicKeyFingerprints = new Set();
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function exactKeys(value, keys, context) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${context}: object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
    `${context}: closed members`,
  );
}

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    assert(Number.isSafeInteger(value), "JCS integer");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  assert(value && typeof value === "object", "JCS value");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

function strictB64(value, width = undefined) {
  assert(typeof value === "string" && /^[A-Za-z0-9_-]*$/.test(value), "strict base64url alphabet");
  assert(!value.includes("="), "strict base64url padding");
  const decoded = Buffer.from(value, "base64url");
  assert(decoded.toString("base64url") === value, "strict base64url canonical");
  if (width !== undefined) assert(decoded.length === width, `strict base64url width ${width}`);
  return decoded;
}

function sha256(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function equalBytes(left, right, context) {
  assert(Buffer.isBuffer(left) && Buffer.isBuffer(right), `${context}: bytes`);
  assert(left.length === right.length, `${context}: width`);
  assert(timingSafeEqual(left, right), `${context}: mismatch`);
}

function parseCanonicalJson(bytes, context) {
  const text = bytes.toString("utf8");
  assert(Buffer.from(text, "utf8").equals(bytes), `${context}: UTF-8`);
  const value = parseJsonNoDuplicates(text, context);
  assert(canonical(value) === text, `${context}: canonical bytes`);
  return value;
}

function parseJsonNoDuplicates(text, context) {
  let index = 0;

  function skipWhitespace() {
    while (index < text.length && /[\t\n\r ]/.test(text[index])) index += 1;
  }

  function parseString() {
    assert(text[index] === '"', `${context}: string`);
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index] === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      }
      index += 1;
    }
    fail(`${context}: unterminated string`);
  }

  function parseValue() {
    skipWhitespace();
    if (text[index] === "{") return parseObject();
    if (text[index] === "[") return parseArray();
    if (text[index] === '"') return parseString();

    for (const [literal, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ]) {
      if (text.startsWith(literal, index)) {
        index += literal.length;
        return value;
      }
    }

    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(index));
    assert(match !== null, `${context}: value`);
    index += match[0].length;
    assert(index === text.length || /[\t\n\r ,\]}]/.test(text[index]), `${context}: number`);
    const value = Number(match[0]);
    assert(Number.isFinite(value), `${context}: finite number`);
    return value;
  }

  function parseObject() {
    const names = new Set();
    const value = Object.create(null);
    index += 1;
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return value;
    }
    while (index < text.length) {
      skipWhitespace();
      const name = parseString();
      assert(!names.has(name), `${context}: duplicate JSON member ${name}`);
      names.add(name);
      skipWhitespace();
      assert(text[index] === ":", `${context}: member separator`);
      index += 1;
      value[name] = parseValue();
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return value;
      }
      assert(text[index] === ",", `${context}: object separator`);
      index += 1;
    }
    fail(`${context}: unterminated object`);
  }

  function parseArray() {
    const value = [];
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return value;
    }
    while (index < text.length) {
      value.push(parseValue());
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return value;
      }
      assert(text[index] === ",", `${context}: array separator`);
      index += 1;
    }
    fail(`${context}: unterminated array`);
  }

  const value = parseValue();
  skipWhitespace();
  assert(index === text.length, `${context}: trailing bytes`);
  return value;
}

function decodedBinaryCandidates(value) {
  if (Array.isArray(value)) {
    if (
      value.length >= 48 &&
      value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
    ) {
      return [Buffer.from(value)];
    }
    return [];
  }

  if (typeof value !== "string") return [];
  const candidates = [];

  if (/^[0-9A-Fa-f]{96,}$/.test(value) && value.length % 2 === 0) {
    candidates.push(Buffer.from(value, "hex"));
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length >= 64 && value.length % 4 === 0) {
    candidates.push(Buffer.from(value, "base64"));
  }
  if (/^[A-Za-z0-9_-]{64,}$/.test(value)) {
    candidates.push(Buffer.from(value, "base64url"));
  }

  return candidates;
}

function isEd25519PrivateDer(bytes) {
  if (!isCompleteDerSequence(bytes)) return false;

  try {
    const key = createPrivateKey({key: bytes, format: "der", type: "pkcs8"});
    return key.asymmetricKeyType === "ed25519";
  } catch {
    return false;
  }
}

function isCompleteDerSequence(bytes) {
  if (bytes.length < 2 || bytes[0] !== 0x30) return false;
  const firstLength = bytes[1];
  if ((firstLength & 0x80) === 0) return bytes.length === firstLength + 2;

  const lengthBytes = firstLength & 0x7f;
  if (lengthBytes === 0 || lengthBytes > 4 || bytes.length < 2 + lengthBytes) return false;
  if (bytes[2] === 0) return false;

  let contentLength = 0;
  for (let index = 0; index < lengthBytes; index += 1) {
    contentLength = contentLength * 256 + bytes[2 + index];
  }
  if (contentLength < 128) return false;
  return bytes.length === 2 + lengthBytes + contentLength;
}

function assertNoPrivateMaterial(value, context) {
  if (typeof value === "string") {
    assert(!/-----BEGIN (?:ENCRYPTED |ED25519 )?PRIVATE KEY-----/.test(value), `${context}: private PEM material`);
  }

  for (const candidate of decodedBinaryCandidates(value)) {
    assert(!isEd25519PrivateDer(candidate), `${context}: private Ed25519 DER material`);
  }

  if (Array.isArray(value)) {
    for (const child of value) assertNoPrivateMaterial(child, context);
    return;
  }
  if (!value || typeof value !== "object") return;

  for (const [key, child] of Object.entries(value)) {
    if (/(^|[_-])(d|sk)($|[_-])|private|secret|seed/i.test(key)) {
      assert(
        decodedBinaryCandidates(child).length === 0 &&
          !(typeof child === "string" && child.length > 0),
        `${context}: private key material`,
      );
    }
    assertNoPrivateMaterial(child, context);
  }
}

function fingerprint(publicKey) {
  const jwk = { crv: "Ed25519", kty: "OKP", x: publicKey.toString("base64url") };
  return sha256(Buffer.from(canonical(jwk), "utf8"));
}

function nodePublicKey(raw) {
  assert(raw.length === 32, "Ed25519 public-key width");
  importedPublicKeyFingerprints.add(fingerprint(raw).toString("base64url"));
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function parseCompact(compact, expectedTyp, expectedKid, expectedPayload, publicKey, context) {
  assert(typeof compact === "string" && compact.length <= 8192, `${context}: compact size`);
  const segments = compact.split(".");
  assert(segments.length === 3, `${context}: compact shape`);
  const [protectedSegment, payloadSegment, signatureSegment] = segments;
  const protectedBytes = strictB64(protectedSegment);
  const payloadBytes = strictB64(payloadSegment);
  const signature = strictB64(signatureSegment, 64);
  const header = parseCanonicalJson(protectedBytes, `${context} header`);
  const payload = parseCanonicalJson(payloadBytes, `${context} payload`);
  exactKeys(header, ["alg", "typ", "kid"], `${context} header`);
  assert(header.alg === "EdDSA" && header.typ === expectedTyp, `${context}: protected header`);
  assert(header.kid === expectedKid, `${context}: kid`);
  assert(canonical(payload) === canonical(expectedPayload), `${context}: expected payload`);
  const message = Buffer.from(`${protectedSegment}.${payloadSegment}`, "ascii");
  assert(
    verifySignature(null, message, nodePublicKey(publicKey), signature),
    `${context}: Ed25519 signature`,
  );
  return { header, payload, signature };
}

function expectedAnchorPayload(expected) {
  return {
    anchor_id: expected.anchor_id,
    anchored_at: expected.anchored_at,
    chain_hash: expected.chain_hash,
    chain_id: expected.chain_id,
    key_fingerprint: expected.key_fingerprint,
    sequence: expected.sequence,
    v: 1,
  };
}

function expectedTransitionPayload(expected) {
  return {
    chain_id: expected.chain_id,
    effective_at: expected.effective_at,
    from_key_fingerprint: expected.current_key_fingerprint,
    to_key_fingerprint: expected.next_key_fingerprint,
    to_key_id: expected.next_key_id,
    transition_id: expected.transition_id,
    v: 1,
  };
}

function inWindow(time, key) {
  return (
    Number.isSafeInteger(time) &&
    time >= key.valid_from &&
    (key.valid_before === null || time < key.valid_before)
  );
}

function verifyAnchor(expected, key, context) {
  exactKeys(
    expected,
    [
      "compact",
      "anchor_id",
      "anchored_at",
      "chain_id",
      "sequence",
      "chain_hash",
      "key_id",
      "key_fingerprint",
    ],
    `${context} expected`,
  );
  assert(Number.isSafeInteger(expected.anchored_at), `${context}: anchored_at`);
  assert(Number.isSafeInteger(expected.sequence) && expected.sequence >= 0, `${context}: sequence`);
  assert(
    expected.sequence !== 0 || strictB64(expected.chain_hash, 32).equals(Buffer.alloc(32)),
    `${context}: genesis anchor hash`,
  );
  assert(expected.key_id === key.key_id, `${context}: key ID`);
  const publicKey = strictB64(key.public_key, 32);
  const derived = fingerprint(publicKey);
  equalBytes(derived, strictB64(key.fingerprint, 32), `${context}: key record fingerprint`);
  equalBytes(derived, strictB64(expected.key_fingerprint, 32), `${context}: expected fingerprint`);
  strictB64(expected.chain_hash, 32);
  assert(inWindow(expected.anchored_at, key), `${context}: historical interval`);
  parseCompact(
    expected.compact,
    "ba+chain-anchor",
    key.key_id,
    expectedAnchorPayload(expected),
    publicKey,
    context,
  );
  return {
    version: 1,
    anchor_id: expected.anchor_id,
    anchored_at: expected.anchored_at,
    chain_id: expected.chain_id,
    sequence: expected.sequence,
    chain_hash: expected.chain_hash,
    key_fingerprint: expected.key_fingerprint,
    verification: "signature_and_window",
    trust: "not_evaluated",
  };
}

function verifyTransition(expected, current, next, context) {
  exactKeys(
    expected,
    [
      "compact",
      "transition_id",
      "chain_id",
      "effective_at",
      "current_key_id",
      "current_key_fingerprint",
      "next_key_id",
      "next_key_fingerprint",
    ],
    `${context} expected`,
  );
  assert(expected.current_key_id === current.key_id, `${context}: current key ID`);
  assert(expected.next_key_id === next.key_id, `${context}: next key ID`);
  const currentRaw = strictB64(current.public_key, 32);
  const nextRaw = strictB64(next.public_key, 32);
  const currentFingerprint = fingerprint(currentRaw);
  const nextFingerprint = fingerprint(nextRaw);
  assert(!currentFingerprint.equals(nextFingerprint), `${context}: distinct public keys`);
  equalBytes(
    currentFingerprint,
    strictB64(expected.current_key_fingerprint, 32),
    `${context}: current fingerprint`,
  );
  equalBytes(
    nextFingerprint,
    strictB64(expected.next_key_fingerprint, 32),
    `${context}: next fingerprint`,
  );
  assert(inWindow(expected.effective_at, current), `${context}: current window`);
  assert(inWindow(expected.effective_at, next), `${context}: next window`);
  parseCompact(
    expected.compact,
    "ba+key-transition",
    current.key_id,
    expectedTransitionPayload(expected),
    currentRaw,
    context,
  );
  return {
    version: 1,
    transition_id: expected.transition_id,
    effective_at: expected.effective_at,
    chain_id: expected.chain_id,
    current_key_fingerprint: expected.current_key_fingerprint,
    next_key_fingerprint: expected.next_key_fingerprint,
    verification: "authenticated_transition",
    trust: "not_evaluated",
  };
}

function readFrame(bytes, cursor, maximum, context) {
  assert(cursor + 4 <= bytes.length, `${context}: frame length`);
  const length = bytes.readUInt32BE(cursor);
  assert(length > 0 && length <= maximum, `${context}: frame bound`);
  const start = cursor + 4;
  const end = start + length;
  assert(end <= bytes.length, `${context}: complete frame`);
  return { bytes: bytes.subarray(start, end), next: end };
}

function parseArchive(bytes) {
  assert(bytes.length > ARCHIVE_PREFIX.length && bytes.length <= 270820384, "archive byte bound");
  assert(bytes.subarray(0, ARCHIVE_PREFIX.length).equals(ARCHIVE_PREFIX), "archive prefix");
  let cursor = ARCHIVE_PREFIX.length;
  const headerFrame = readFrame(bytes, cursor, 8192, "archive header");
  cursor = headerFrame.next;
  const header = parseCanonicalJson(headerFrame.bytes, "archive header");
  exactKeys(
    header,
    [
      "v",
      "chain_id",
      "first_sequence",
      "last_sequence",
      "row_count",
      "transition_count",
      "previous_hash",
      "last_hash",
    ],
    "archive header",
  );
  assert(header.v === 1, "archive version");
  assert(
    Number.isSafeInteger(header.first_sequence) &&
      Number.isSafeInteger(header.last_sequence) &&
      Number.isSafeInteger(header.row_count) &&
      header.first_sequence > 0 &&
      header.last_sequence >= header.first_sequence &&
      header.row_count === header.last_sequence - header.first_sequence + 1 &&
      header.row_count <= 65536,
    "archive row range",
  );
  assert(
    Number.isSafeInteger(header.transition_count) &&
      header.transition_count >= 0 &&
      header.transition_count <= 256,
    "archive transition count",
  );
  strictB64(header.previous_hash, 32);
  strictB64(header.last_hash, 32);

  const startFrame = readFrame(bytes, cursor, 8192, "start anchor");
  cursor = startFrame.next;
  const transitionFrames = [];
  for (let index = 0; index < header.transition_count; index += 1) {
    const frame = readFrame(bytes, cursor, 8192, `transition ${index}`);
    transitionFrames.push(frame.bytes);
    cursor = frame.next;
  }
  const rowFrames = [];
  for (let index = 0; index < header.row_count; index += 1) {
    const frame = readFrame(bytes, cursor, 4096, `row ${index}`);
    rowFrames.push(frame.bytes);
    cursor = frame.next;
  }
  const endFrame = readFrame(bytes, cursor, 8192, "end anchor");
  cursor = endFrame.next;
  assert(cursor === bytes.length, "archive exact EOF");
  return {
    header,
    headerBytes: headerFrame.bytes,
    start: startFrame.bytes,
    transitions: transitionFrames,
    rows: rowFrames,
    end: endFrame.bytes,
  };
}

function frame(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function encodeParsedArchive(parsed) {
  return Buffer.concat([
    ARCHIVE_PREFIX,
    frame(parsed.headerBytes),
    frame(parsed.start),
    ...parsed.transitions.map(frame),
    ...parsed.rows.map(frame),
    frame(parsed.end),
  ]);
}

function verifyChain(rows, expected) {
  exactKeys(
    expected,
    [
      "chain_id",
      "first_sequence",
      "last_sequence",
      "row_count",
      "previous_hash",
      "last_hash",
    ],
    "expected chain",
  );
  assert(rows.length === expected.row_count && rows.length > 0, "chain row count");
  assert(
    expected.last_sequence === expected.first_sequence + expected.row_count - 1,
    "chain expected range",
  );
  let previous = strictB64(expected.previous_hash, 32);
  assert(
    expected.first_sequence !== 1 || previous.equals(Buffer.alloc(32)),
    "chain genesis predecessor",
  );
  let sequence = expected.first_sequence;
  for (const [index, bytes] of rows.entries()) {
    const row = parseCanonicalJson(bytes, `row ${index}`);
    exactKeys(row, ["v", "chain_id", "sequence", "previous", "commitment"], `row ${index}`);
    assert(row.v === 1 && row.chain_id === expected.chain_id, `row ${index}: identity`);
    assert(row.sequence === sequence, `row ${index}: sequence`);
    equalBytes(strictB64(row.previous, 32), previous, `row ${index}: previous link`);
    strictB64(row.commitment, 32);
    previous = sha256(ROW_PREFIX, bytes);
    sequence += 1;
  }
  equalBytes(previous, strictB64(expected.last_hash, 32), "chain head");
  return {
    version: 1,
    chain_id: expected.chain_id,
    first_sequence: expected.first_sequence,
    last_sequence: expected.last_sequence,
    row_count: expected.row_count,
    previous_hash: expected.previous_hash,
    last_hash: expected.last_hash,
    verification: "boundary_consistent",
    trust: "not_evaluated",
  };
}

function keyRecord(raw) {
  exactKeys(
    raw,
    ["key_id", "public_key", "fingerprint", "valid_from", "valid_before"],
    "historical key",
  );
  assert(Number.isSafeInteger(raw.valid_from), "historical valid_from");
  assert(
    raw.valid_before === null ||
      (Number.isSafeInteger(raw.valid_before) && raw.valid_before > raw.valid_from),
    "historical valid_before",
  );
  const publicKey = strictB64(raw.public_key, 32);
  equalBytes(fingerprint(publicKey), strictB64(raw.fingerprint, 32), "historical fingerprint");
  return raw;
}

function verifyArchive(
  rawCase,
  overrideChain = undefined,
  observedVersion = rawCase.object_version,
  expectedVersion = rawCase.object_version,
) {
  const archive = strictB64(rawCase.archive_base64url);
  assert(archive.length === rawCase.archive_byte_count, `${rawCase.name}: byte count`);
  equalBytes(sha256(archive), strictB64(rawCase.archive_digest, 32), `${rawCase.name}: digest`);
  assert(
    typeof observedVersion === "string" && observedVersion.length > 0,
    `${rawCase.name}: observed object version`,
  );
  assert(
    typeof expectedVersion === "string" && expectedVersion.length > 0,
    `${rawCase.name}: expected object version`,
  );
  assert(observedVersion === expectedVersion, `${rawCase.name}: object version mismatch`);
  const parsed = parseArchive(archive);
  const expectedChain = overrideChain ?? rawCase.chain;
  assert(canonical(parsed.header) === canonical({
    chain_id: expectedChain.chain_id,
    first_sequence: expectedChain.first_sequence,
    last_hash: expectedChain.last_hash,
    last_sequence: expectedChain.last_sequence,
    previous_hash: expectedChain.previous_hash,
    row_count: expectedChain.row_count,
    transition_count: rawCase.transitions.length,
    v: 1,
  }), `${rawCase.name}: authenticated archive header`);
  assert(parsed.start.toString("ascii") === rawCase.start_anchor.compact, `${rawCase.name}: start bytes`);
  assert(parsed.end.toString("ascii") === rawCase.end_anchor.compact, `${rawCase.name}: end bytes`);
  assert(
    parsed.transitions.every(
      (bytes, index) => bytes.toString("ascii") === rawCase.transitions[index].compact,
    ),
    `${rawCase.name}: transition bytes`,
  );
  const keys = rawCase.historical_keys.map(keyRecord);
  assert(keys.length === rawCase.transitions.length + 1, `${rawCase.name}: key count`);
  assert(
    new Set(keys.map((key) => key.fingerprint)).size === keys.length,
    `${rawCase.name}: key cycle`,
  );
  const startAnchorFacts = verifyAnchor(
    rawCase.start_anchor,
    keys[0],
    `${rawCase.name} start`,
  );
  let lastTime = rawCase.start_anchor.anchored_at;
  const transitionFacts = [];
  rawCase.transitions.forEach((transition, index) => {
    assert(
      transition.chain_id === expectedChain.chain_id,
      `${rawCase.name}: transition chain identity`,
    );
    transitionFacts.push(
      verifyTransition(
        transition,
        keys[index],
        keys[index + 1],
        `${rawCase.name} transition ${index}`,
      ),
    );
    assert(transition.effective_at > lastTime, `${rawCase.name}: increasing transition time`);
    lastTime = transition.effective_at;
  });
  const endAnchorFacts = verifyAnchor(
    rawCase.end_anchor,
    keys[keys.length - 1],
    `${rawCase.name} end`,
  );
  assert(rawCase.end_anchor.anchored_at >= lastTime, `${rawCase.name}: end chronology`);
  assert(
    rawCase.start_anchor.chain_id === expectedChain.chain_id &&
      rawCase.start_anchor.sequence === expectedChain.first_sequence - 1 &&
      rawCase.start_anchor.chain_hash === expectedChain.previous_hash,
    `${rawCase.name}: start boundary`,
  );
  assert(
    rawCase.end_anchor.chain_id === expectedChain.chain_id &&
      rawCase.end_anchor.sequence === expectedChain.last_sequence &&
      rawCase.end_anchor.chain_hash === expectedChain.last_hash,
    `${rawCase.name}: end boundary`,
  );
  const chainFacts = verifyChain(parsed.rows, expectedChain);
  const anchoredExportFacts = {
    version: 1,
    chain_id: expectedChain.chain_id,
    first_sequence: expectedChain.first_sequence,
    last_sequence: expectedChain.last_sequence,
    row_count: expectedChain.row_count,
    previous_hash: expectedChain.previous_hash,
    last_hash: expectedChain.last_hash,
    digest: sha256(archive).toString("base64url"),
    start_anchor_id: rawCase.start_anchor.anchor_id,
    start_anchored_at: rawCase.start_anchor.anchored_at,
    start_key_fingerprint: rawCase.start_anchor.key_fingerprint,
    end_anchor_id: rawCase.end_anchor.anchor_id,
    end_anchored_at: rawCase.end_anchor.anchored_at,
    end_key_fingerprint: rawCase.end_anchor.key_fingerprint,
    transition_count: rawCase.transitions.length,
    verification: "anchored_export",
    trust: "not_evaluated",
    authorization: "not_evaluated",
  };
  const facts = {
    chain: chainFacts,
    start_anchor: startAnchorFacts,
    transitions: transitionFacts,
    end_anchor: endAnchorFacts,
    anchored_export: anchoredExportFacts,
  };
  assert(rawCase.facts !== undefined, `${rawCase.name}: published facts`);
  assert(canonical(facts) === canonical(rawCase.facts), `${rawCase.name}: exact facts`);
  return facts;
}

function clone(value) {
  return structuredClone(value);
}

function expectInvalid(label, mutate, sourceCase, expectedMessage = undefined) {
  const changed = clone(sourceCase);
  mutate(changed);
  try {
    verifyArchive(changed);
  } catch (error) {
    if (expectedMessage !== undefined) {
      assert(error.message.includes(expectedMessage), `${label}: rejection stage`);
    }
    return;
  }
  fail(`tamper accepted: ${label}`);
}

function expectFailure(label, operation, expectedMessage) {
  try {
    operation();
  } catch (error) {
    assert(error.message.includes(expectedMessage), `${label}: rejection stage`);
    return;
  }
  fail(`invalid semantic case accepted: ${label}`);
}

function replaceArchive(rawCase, bytes) {
  rawCase.archive_base64url = bytes.toString("base64url");
  rawCase.archive_byte_count = bytes.length;
  rawCase.archive_digest = sha256(bytes).toString("base64url");
}

function mutateCompactPayload(compact, field) {
  const segments = compact.split(".");
  assert(segments.length === 3, "payload tamper compact shape");
  const payload = parseCanonicalJson(strictB64(segments[1]), "payload tamper source");
  const decoded = Buffer.from(strictB64(payload[field], 32));
  decoded[0] ^= 1;
  payload[field] = decoded.toString("base64url");
  segments[1] = Buffer.from(canonical(payload), "utf8").toString("base64url");
  return segments.join(".");
}

function mutateCompactProtected(compact, field, value) {
  const segments = compact.split(".");
  assert(segments.length === 3, "protected-header tamper compact shape");
  const protectedHeader = parseCanonicalJson(
    strictB64(segments[0]),
    "protected-header tamper source",
  );
  protectedHeader[field] = value;
  segments[0] = Buffer.from(canonical(protectedHeader), "utf8").toString("base64url");
  return segments.join(".");
}

function mutateCompactSignature(compact) {
  const segments = compact.split(".");
  assert(segments.length === 3, "signature tamper compact shape");
  const signature = Buffer.from(strictB64(segments[2], 64));
  signature[32] ^= 1;
  segments[2] = signature.toString("base64url");
  return segments.join(".");
}

function replaceCompact(rawCase, target, mutate, transitionIndex = 0) {
  const parsed = parseArchive(strictB64(rawCase.archive_base64url));

  if (target === "start") {
    rawCase.start_anchor.compact = mutate(rawCase.start_anchor.compact);
    parsed.start = Buffer.from(rawCase.start_anchor.compact, "ascii");
  } else if (target === "end") {
    rawCase.end_anchor.compact = mutate(rawCase.end_anchor.compact);
    parsed.end = Buffer.from(rawCase.end_anchor.compact, "ascii");
  } else {
    rawCase.transitions[transitionIndex].compact = mutate(
      rawCase.transitions[transitionIndex].compact,
    );
    parsed.transitions[transitionIndex] = Buffer.from(
      rawCase.transitions[transitionIndex].compact,
      "ascii",
    );
  }

  replaceArchive(rawCase, encodeParsedArchive(parsed));
}

function runTamperMatrix(fixture) {
  const one = fixture.archives.find((entry) => entry.name === "one-step-rollover");
  const multi = fixture.archives.find((entry) => entry.name === "multi-step-rollover");
  const publishedInvalidCases = fixture.verdicts.invalid_cases;
  const observedInvalidCases = new Set();
  let cases = 0;
  const invalid = (label, mutation, source = one, expectedMessage = undefined) => {
    assert(publishedInvalidCases[label] === "invalid", `${label}: published invalid verdict`);
    assert(!observedInvalidCases.has(label), `${label}: duplicate invalid case`);
    expectInvalid(label, mutation, source, expectedMessage);
    observedInvalidCases.add(label);
    cases += 1;
  };

  invalid("truncation", (entry) => {
    const bytes = strictB64(entry.archive_base64url);
    replaceArchive(entry, bytes.subarray(0, bytes.length - 1));
  });
  invalid("prefix", (entry) => {
    const bytes = Buffer.from(strictB64(entry.archive_base64url));
    bytes[0] ^= 1;
    replaceArchive(entry, bytes);
  });
  invalid("archive prefix version", (entry) => {
    const bytes = Buffer.from(strictB64(entry.archive_base64url));
    bytes[3] = "2".charCodeAt(0);
    replaceArchive(entry, bytes);
  });
  invalid("frame length", (entry) => {
    const bytes = Buffer.from(strictB64(entry.archive_base64url));
    bytes.writeUInt32BE(0xffffffff, ARCHIVE_PREFIX.length);
    replaceArchive(entry, bytes);
  });
  invalid("commitment bytes", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    const marker = parsed.rows[0].indexOf(Buffer.from('"commitment":"'));
    parsed.rows[0][marker + 15] ^= 1;
    replaceArchive(entry, encodeParsedArchive(parsed));
  });
  invalid("previous link bytes", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    const marker = parsed.rows[1].indexOf(Buffer.from('"previous":"'));
    parsed.rows[1][marker + 17] ^= 1;
    replaceArchive(entry, encodeParsedArchive(parsed));
  });
  invalid("row reorder", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    [parsed.rows[0], parsed.rows[1]] = [parsed.rows[1], parsed.rows[0]];
    replaceArchive(entry, encodeParsedArchive(parsed));
  });
  invalid("removed first row", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    parsed.rows.shift();
    replaceArchive(entry, encodeParsedArchive(parsed));
  });
  invalid("removed final row", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    parsed.rows.pop();
    replaceArchive(entry, encodeParsedArchive(parsed));
  });
  invalid("removed middle row", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    parsed.rows.splice(1, 1);
    replaceArchive(entry, encodeParsedArchive(parsed));
  });
  invalid("missing end anchor", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    const bytes = Buffer.concat([
      ARCHIVE_PREFIX,
      frame(parsed.headerBytes),
      frame(parsed.start),
      ...parsed.transitions.map(frame),
      ...parsed.rows.map(frame),
    ]);
    replaceArchive(entry, bytes);
  });
  invalid("trailing byte exact EOF", (entry) => {
    const bytes = Buffer.concat([
      strictB64(entry.archive_base64url),
      Buffer.from([0]),
    ]);
    replaceArchive(entry, bytes);
  });
  invalid("start anchor payload bytes", (entry) => {
    replaceCompact(entry, "start", (compact) => mutateCompactPayload(compact, "chain_hash"));
  }, one, "expected payload");
  invalid("start anchor signature bytes", (entry) => {
    replaceCompact(entry, "start", mutateCompactSignature);
  }, one, "Ed25519 signature");
  invalid("end anchor payload bytes", (entry) => {
    replaceCompact(entry, "end", (compact) => mutateCompactPayload(compact, "chain_hash"));
  }, one, "expected payload");
  invalid("end anchor signature bytes", (entry) => {
    replaceCompact(entry, "end", mutateCompactSignature);
  }, one, "Ed25519 signature");
  invalid("transition payload bytes", (entry) => {
    replaceCompact(entry, "transition", (compact) =>
      mutateCompactPayload(compact, "to_key_fingerprint"),
    );
  }, one, "expected payload");
  invalid("transition signature bytes", (entry) => {
    replaceCompact(entry, "transition", mutateCompactSignature);
  }, one, "Ed25519 signature");
  invalid("swapped transition kid", (entry) => {
    replaceCompact(entry, "transition", (compact) =>
      mutateCompactProtected(compact, "kid", entry.transitions[0].next_key_id),
    );
  }, one, "kid");
  invalid("swapped transition fingerprints", (entry) => {
    const transition = entry.transitions[0];
    [transition.current_key_fingerprint, transition.next_key_fingerprint] = [
      transition.next_key_fingerprint,
      transition.current_key_fingerprint,
    ];
  });
  invalid("public key", (entry) => {
    const raw = strictB64(entry.historical_keys[0].public_key, 32);
    raw[0] ^= 1;
    entry.historical_keys[0].public_key = raw.toString("base64url");
  });
  invalid("swapped historical public keys", (entry) => {
    [entry.historical_keys[0].public_key, entry.historical_keys[1].public_key] = [
      entry.historical_keys[1].public_key,
      entry.historical_keys[0].public_key,
    ];
  });
  invalid("swapped key records", (entry) => {
    [entry.historical_keys[0], entry.historical_keys[1]] = [
      entry.historical_keys[1],
      entry.historical_keys[0],
    ];
  });
  invalid("missing transition", (entry) => {
    entry.transitions = [];
  });
  invalid("duplicated transition", (entry) => {
    entry.transitions.push(clone(entry.transitions[0]));
    entry.historical_keys.push(clone(entry.historical_keys[1]));
  });
  invalid("reordered transitions", (entry) => {
    entry.transitions.reverse();
  }, multi);
  invalid("unauthenticated A-to-C jump", (entry) => {
    entry.transitions = [entry.transitions[0]];
    entry.historical_keys = [entry.historical_keys[0], entry.historical_keys[2]];
  }, multi);
  invalid("key cycle", (entry) => {
    entry.historical_keys[2] = clone(entry.historical_keys[0]);
    entry.historical_keys[2].key_id = "archive-key-cycle-alias";
  }, multi);
  invalid("non-increasing transition time", (entry) => {
    entry.transitions[1].effective_at = entry.transitions[0].effective_at;
  }, multi);
  invalid("transition outside next window", (entry) => {
    entry.historical_keys[1].valid_from = entry.transitions[0].effective_at + 1;
  });
  invalid("transition outside current window", (entry) => {
    entry.historical_keys[0].valid_before = entry.transitions[0].effective_at;
  });
  invalid("reverse-time boundary", (entry) => {
    entry.end_anchor.anchored_at = entry.start_anchor.anchored_at - 1;
  });
  invalid("negative anchor sequence", (entry) => {
    entry.start_anchor.sequence = -1;
  });
  invalid("sequence-zero nonzero hash", (entry) => {
    entry.start_anchor.chain_hash = Buffer.alloc(32, 1).toString("base64url");
  });
  invalid("expected first sequence", (entry) => {
    entry.chain.first_sequence += 1;
  });
  invalid("expected last sequence", (entry) => {
    entry.chain.last_sequence -= 1;
  });
  invalid("expected row count", (entry) => {
    entry.chain.row_count -= 1;
  });
  invalid("expected predecessor", (entry) => {
    entry.chain.previous_hash = Buffer.alloc(32, 1).toString("base64url");
  });
  invalid("expected head", (entry) => {
    entry.chain.last_hash = Buffer.alloc(32).toString("base64url");
  });
  invalid("expected chain ID", (entry) => {
    entry.chain.chain_id = `${entry.chain.chain_id}:drift`;
  });
  invalid("expected start anchor ID", (entry) => {
    entry.start_anchor.anchor_id = `${entry.start_anchor.anchor_id}:drift`;
  });
  invalid("expected end anchor ID", (entry) => {
    entry.end_anchor.anchor_id = `${entry.end_anchor.anchor_id}:drift`;
  });
  invalid("expected start anchor boundary", (entry) => {
    entry.start_anchor.sequence += 1;
  });
  invalid("expected end anchor boundary", (entry) => {
    entry.end_anchor.sequence -= 1;
  });
  invalid("transition maximum plus one", (entry) => {
    const parsed = parseArchive(strictB64(entry.archive_base64url));
    parsed.header.transition_count = 257;
    parsed.headerBytes = Buffer.from(canonical(parsed.header), "utf8");
    replaceArchive(entry, encodeParsedArchive(parsed));
  }, one, "archive transition count");
  invalid("archive digest", (entry) => {
    entry.archive_digest = Buffer.alloc(32).toString("base64url");
  });
  const objectVersionLabel = "object version mismatch";
  assert(
    publishedInvalidCases[objectVersionLabel] === "invalid",
    `${objectVersionLabel}: published invalid verdict`,
  );
  expectFailure(
    objectVersionLabel,
    () =>
      verifyArchive(
        one,
        undefined,
        `${one.object_version}-observed-drift`,
        one.object_version,
    ),
    "object version mismatch",
  );
  observedInvalidCases.add(objectVersionLabel);
  cases += 1;

  for (const adversary of fixture.boundary_adversaries) {
    const label = `${adversary.name} against full expectation`;
    assert(publishedInvalidCases[label] === "invalid", `${label}: published invalid verdict`);
    verifyArchive(adversary);
    try {
      verifyArchive(adversary, fixture.chains.genesis.expected);
    } catch {
      observedInvalidCases.add(label);
      cases += 1;
      continue;
    }
    fail(`boundary adversary accepted against full expectation: ${adversary.name}`);
  }
  assert(
    canonical([...observedInvalidCases].sort()) ===
      canonical(Object.keys(publishedInvalidCases).sort()),
    "published invalid-case set",
  );
  return cases;
}

function verifySemanticEdges(fixture) {
  exactKeys(
    fixture,
    [
      "format",
      "provenance",
      "valid_same_id_equal_time_archive",
      "signed_cross_chain_archive",
      "signed_reverse_time_archive",
      "signed_invalid_genesis_anchor",
      "invalid_genesis_chain",
      "signed_transition_before_start_archive",
      "signed_transition_after_end_archive",
      "verdicts",
    ],
    "semantic edge fixture",
  );
  assert(
    fixture.format === "bounded-authority-protocol-v1-chain-semantic-edge",
    "semantic edge format",
  );
  assert(fixture.provenance.private_material_tracked === false, "semantic edge private material");
  exactKeys(
    fixture.verdicts,
    [
      "invalid_genesis_chain",
      "signed_cross_chain_archive",
      "signed_invalid_genesis_anchor",
      "signed_reverse_time_archive",
      "signed_transition_after_end_archive",
      "signed_transition_before_start_archive",
      "valid_same_id_equal_time_archive",
    ],
    "semantic edge verdicts",
  );
  assert(
    fixture.verdicts.valid_same_id_equal_time_archive === "valid" &&
      Object.entries(fixture.verdicts)
        .filter(([name]) => name !== "valid_same_id_equal_time_archive")
        .every(([_name, verdict]) => verdict === "invalid"),
    "semantic edge verdict values",
  );

  verifyArchive(fixture.valid_same_id_equal_time_archive);

  const cross = fixture.signed_cross_chain_archive;
  const crossKeys = cross.historical_keys.map(keyRecord);
  verifyTransition(
    cross.transitions[0],
    crossKeys[0],
    crossKeys[1],
    "signed cross-chain transition",
  );
  expectFailure(
    "signed cross-chain transition",
    () => verifyArchive(cross),
    "transition chain identity",
  );

  const reverse = fixture.signed_reverse_time_archive;
  const reverseKeys = reverse.historical_keys.map(keyRecord);
  verifyAnchor(reverse.start_anchor, reverseKeys[0], "signed reverse-time start");
  verifyTransition(
    reverse.transitions[0],
    reverseKeys[0],
    reverseKeys[1],
    "signed reverse-time transition",
  );
  verifyAnchor(reverse.end_anchor, reverseKeys[1], "signed reverse-time end");
  expectFailure(
    "signed reverse-time boundary",
    () => verifyArchive(reverse),
    "end chronology",
  );

  const invalidAnchor = fixture.signed_invalid_genesis_anchor.anchor;
  const anchorKey = keyRecord(fixture.signed_invalid_genesis_anchor.historical_key);
  parseCompact(
    invalidAnchor.compact,
    "ba+chain-anchor",
    anchorKey.key_id,
    expectedAnchorPayload(invalidAnchor),
    strictB64(anchorKey.public_key, 32),
    "signed invalid genesis anchor signature proof",
  );
  expectFailure(
    "signed invalid genesis anchor",
    () => verifyAnchor(invalidAnchor, anchorKey, "signed invalid genesis anchor"),
    "genesis anchor hash",
  );

  const invalidChain = fixture.invalid_genesis_chain;
  const invalidRows = invalidChain.rows.map((row) => strictB64(row));
  parseCanonicalJson(invalidRows[0], "invalid genesis row canonical proof");
  expectFailure(
    "invalid genesis predecessor",
    () => verifyChain(invalidRows, invalidChain.expected),
    "chain genesis predecessor",
  );

  const chronologyCases = [
    [
      "signed transition before start",
      fixture.signed_transition_before_start_archive,
      "increasing transition time",
    ],
    [
      "signed transition after end",
      fixture.signed_transition_after_end_archive,
      "end chronology",
    ],
  ];

  for (const [label, chronology, expectedMessage] of chronologyCases) {
    const chronologyKeys = chronology.historical_keys.map(keyRecord);
    verifyAnchor(chronology.start_anchor, chronologyKeys[0], `${label} start`);
    verifyTransition(
      chronology.transitions[0],
      chronologyKeys[0],
      chronologyKeys[1],
      `${label} transition`,
    );
    verifyAnchor(chronology.end_anchor, chronologyKeys[1], `${label} end`);
    expectFailure(label, () => verifyArchive(chronology), expectedMessage);
  }

  return 7;
}

function verifyPublishedVerdicts(verdicts) {
  exactKeys(
    verdicts,
    [
      "boundary_adversaries_against_full_chain_expectations",
      "boundary_adversaries_with_own_expectations",
      "canonical_cases",
      "independent_valid_chains",
      "invalid_cases",
    ],
    "fixture verdicts",
  );
  assert(verdicts.canonical_cases === "valid", "canonical-case verdict");
  assert(
    verdicts.boundary_adversaries_with_own_expectations === "valid",
    "boundary own-expectation verdict",
  );
  assert(
    verdicts.boundary_adversaries_against_full_chain_expectations === "invalid",
    "boundary full-expectation verdict",
  );
  assert(
    canonical(verdicts.independent_valid_chains) ===
      canonical({ continuation: "valid", genesis: "valid" }),
    "published valid-chain verdicts",
  );
  exactKeys(
    verdicts.invalid_cases,
    Object.keys(verdicts.invalid_cases),
    "published invalid-case verdicts",
  );
  assert(
    Object.keys(verdicts.invalid_cases).length > 0 &&
      Object.values(verdicts.invalid_cases).every((verdict) => verdict === "invalid"),
    "published invalid-case verdict values",
  );
}

function verifyPublishedChains(chains, verdicts) {
  exactKeys(chains, ["continuation", "genesis"], "published chains");
  let cases = 0;
  for (const name of ["continuation", "genesis"]) {
    const chain = chains[name];
    exactKeys(chain, ["expected", "facts", "row_hashes", "rows"], `${name} chain fixture`);
    assert(verdicts.independent_valid_chains[name] === "valid", `${name}: chain verdict`);
    const facts = verifyChain(
      chain.rows.map((row) => strictB64(row)),
      chain.expected,
    );
    assert(canonical(facts) === canonical(chain.facts), `${name}: exact chain facts`);
    cases += 1;
  }
  return cases;
}

function collectFixtureFingerprints(value, accumulator = new Set()) {
  if (Array.isArray(value)) {
    for (const child of value) collectFixtureFingerprints(child, accumulator);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (
        (key === "raw_base64url" || key === "public_key") &&
        typeof child === "string"
      ) {
        const raw = strictB64(child);
        if (raw.length === 32) accumulator.add(fingerprint(raw).toString("base64url"));
      }
      collectFixtureFingerprints(child, accumulator);
    }
  }
  return accumulator;
}

function rawKey(value) {
  if (typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value)) {
    try {
      const decoded = strictB64(value);
      return decoded.length === 32 ? decoded : null;
    } catch {
      return null;
    }
  }
  if (typeof value === "string" && /^[0-9A-Fa-f]{64}$/.test(value)) {
    return Buffer.from(value, "hex");
  }
  if (
    Array.isArray(value) &&
    value.length === 32 &&
    value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
  ) {
    return Buffer.from(value);
  }
  return null;
}

function publicKeyLabel(key) {
  if (/fingerprint|thumbprint|digest|hash/i.test(key)) return false;
  return (
    /public.*key|key.*public|verification.*key|holder.*key|issuer.*key/i.test(key) ||
    ["raw_base64url", "raw_hex", "raw_bytes"].includes(key)
  );
}

function discoverJsonKeys(value, fingerprints) {
  if (Array.isArray(value)) {
    for (const child of value) discoverJsonKeys(child, fingerprints);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (value.kty === "OKP" && value.crv === "Ed25519" && typeof value.x === "string") {
    fingerprints.add(fingerprint(strictB64(value.x, 32)).toString("base64url"));
  }
  for (const [key, child] of Object.entries(value)) {
    if (publicKeyLabel(key)) {
      const decoded = rawKey(child);
      if (decoded) fingerprints.add(fingerprint(decoded).toString("base64url"));
    }
    discoverJsonKeys(child, fingerprints);
  }
}

function discoverTextKeys(text, fingerprints) {
  const base64Pattern =
    /(?:public[_-]?key(?:[_-]?base64url)?|raw[_-]?base64url|holder[_-]?public[_-]?key|issuer[_-]?public[_-]?key|verification[_-]?key|["']x["']|\bx)\s*(?::|=>|=)\s*["']([A-Za-z0-9_-]{43})["']/gi;
  for (const match of text.matchAll(base64Pattern)) {
    const decoded = rawKey(match[1]);
    if (decoded) fingerprints.add(fingerprint(decoded).toString("base64url"));
  }
  const hexPattern =
    /(?:public[_-]?key(?:[_-]?hex)?|holder[_-]?public[_-]?key|issuer[_-]?public[_-]?key|verification[_-]?key)\s*(?::|=>|=)\s*["']([0-9A-Fa-f]{64})["']/gi;
  for (const match of text.matchAll(hexPattern)) {
    fingerprints.add(fingerprint(Buffer.from(match[1], "hex")).toString("base64url"));
  }
}

function discoverPublicKeys(path, manifestPath, fingerprints) {
  if (resolve(path) === resolve(manifestPath)) return;
  if (statSync(path).isDirectory()) {
    for (const name of readdirSync(path)) {
      discoverPublicKeys(join(path, name), manifestPath, fingerprints);
    }
    return;
  }
  const bytes = readFileSync(path);
  if (extname(path) === ".json") {
    const value = parseJsonNoDuplicates(bytes.toString("utf8"), `census JSON ${path}`);
    assertNoPrivateMaterial(value, `census JSON ${path}`);
    discoverJsonKeys(value, fingerprints);
  } else {
    discoverTextKeys(bytes.toString("utf8"), fingerprints);
  }
}

function verifyManifest(manifest, fixture, fixturePath, additionalScanPath) {
  exactKeys(
    manifest,
    [
      "format",
      "vectors",
      "canonical_public_key_fingerprints",
      "verifier_public_key_fingerprints",
      "discovery_roots",
    ],
    "manifest",
  );
  assert(manifest.format === "bounded-authority-protocol-v1-vector-manifest", "manifest format");
  assert(
    canonical(manifest.vectors) ===
      canonical([
        "chain-semantic-edge.json",
        "consumption-chain-archive.json",
        "grant-holder-proof.json",
      ]),
    "manifest vector set mismatch",
  );
  exactKeys(
    manifest.verifier_public_key_fingerprints,
    ["bap03_independent.mjs", "chain_archive_independent.mjs"],
    "manifest verifier fingerprints",
  );
  assert(
    canonical(manifest.discovery_roots) ===
      canonical([
        "priv/conformance/v1/vectors",
        "priv/conformance/v1/schemas",
        "conformance",
        "test",
      ]),
    "manifest discovery roots mismatch",
  );
  const manifestPath = join(dirname(fixturePath), "manifest.json");
  const discovered = new Set();
  for (const relativeRoot of manifest.discovery_roots) {
    const absolute = resolve(repositoryRoot, relativeRoot);
    assert(
      absolute === repositoryRoot || absolute.startsWith(`${repositoryRoot}/`),
      "manifest discovery root escape",
    );
    discoverPublicKeys(absolute, manifestPath, discovered);
  }
  if (additionalScanPath !== null) {
    discoverPublicKeys(resolve(additionalScanPath), manifestPath, discovered);
  }
  collectFixtureFingerprints(fixture, discovered);

  const verifierSets = Object.values(manifest.verifier_public_key_fingerprints);
  for (const verifierSet of verifierSets) {
    assert(
      canonical(verifierSet) === canonical([...new Set(verifierSet)].sort()),
      "manifest verifier fingerprint set not sorted",
    );
  }

  const declared = [...manifest.canonical_public_key_fingerprints];
  assert(canonical(declared) === canonical([...new Set(declared)].sort()), "manifest set not sorted");
  const verifierUnion = [...new Set(verifierSets.flat())].sort();
  assert(
    canonical(declared) === canonical(verifierUnion),
    "manifest public-key fingerprint set mismatch",
  );

  const expectedImports =
    manifest.verifier_public_key_fingerprints["chain_archive_independent.mjs"];
  const actualImports = [...importedPublicKeyFingerprints].sort();
  assert(
    canonical(expectedImports) === canonical(actualImports),
    "manifest verifier import set mismatch",
  );

  const discoveredFingerprints = [...discovered].sort();
  assert(
    canonical(declared) === canonical(discoveredFingerprints),
    "manifest discovered public-key fingerprint set mismatch",
  );
  return declared.length;
}

function main() {
  const arguments_ = process.argv.slice(2);
  assert(
    arguments_.length === 2 ||
      (arguments_.length === 4 && arguments_[2] === "--scan"),
    "usage: chain_archive_independent.mjs FIXTURE MANIFEST [--scan PATH]",
  );
  const fixturePath = resolve(arguments_[0]);
  const manifestPath = resolve(arguments_[1]);
  const additionalScanPath = arguments_.length === 4 ? arguments_[3] : null;
  const fixture = parseJsonNoDuplicates(readFileSync(fixturePath, "utf8"), `fixture ${fixturePath}`);
  const semanticFixture = parseJsonNoDuplicates(
    readFileSync(
      join(repositoryRoot, "priv/conformance/v1/vectors/chain-semantic-edge.json"),
      "utf8",
    ),
    "semantic fixture",
  );
  const manifest = parseJsonNoDuplicates(readFileSync(manifestPath, "utf8"), `manifest ${manifestPath}`);
  assertNoPrivateMaterial(fixture, "fixture");
  assertNoPrivateMaterial(semanticFixture, "semantic fixture");
  assertNoPrivateMaterial(manifest, "manifest");
  exactKeys(
    fixture,
    ["format", "provenance", "public_keys", "chains", "archives", "boundary_adversaries", "verdicts"],
    "fixture",
  );
  assert(
    fixture.format === "bounded-authority-protocol-v1-consumption-chain-archive",
    "fixture format",
  );
  assert(fixture.provenance.private_material_tracked === false, "fixture private material");
  verifyPublishedVerdicts(fixture.verdicts);
  const chainCases = verifyPublishedChains(fixture.chains, fixture.verdicts);
  for (const entry of fixture.archives) verifyArchive(entry);
  const semanticCases = verifySemanticEdges(semanticFixture);
  const tamperCases = runTamperMatrix(fixture);
  const fingerprints = verifyManifest(manifest, fixture, fixturePath, additionalScanPath);
  process.stdout.write(
      `bap04 independent verification: ok archives=${fixture.archives.length} ` +
      `boundary_adversaries=${fixture.boundary_adversaries.length} ` +
      `chain_cases=${chainCases} public_key_fingerprints=${fingerprints} ` +
      `tamper_cases=${tamperCases} ` +
      `semantic_cases=${semanticCases}\n`,
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`bap04 independent verification: error: ${error.message}\n`);
  process.exitCode = 1;
}
