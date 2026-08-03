// Independent second-implementation conformance corpus verifier (BAP-05 Task 4).
//
// Recomputes the v1 conformance corpus from scratch using only node:* primitives.
// Imports NO project code. Re-verifies corpus integrity (per-file SHA-256, exact
// file-set equality both directions, counts, case-id uniqueness, applicability
// totality both directions, `.raw` hash binding) and, for every case, independently
// recomputes the surface result and checks agreement with the case-declared
// expectation. Census: the public keys observed at the node:crypto import boundary
// must equal the corpus index's `public_key_fingerprints` exactly, both directions,
// always (hard two-way — a vacuous green is the V4 hole this design exists to kill).
// With `--manifest`, additionally partition + three-partition union equality.

import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ARCHIVE_PREFIX = Buffer.from("BAP1-ARCHIVE\0EXPORT\0", "binary");
const ROW_PREFIX = Buffer.from("BAP1-CHAIN\0", "binary");
const REQUEST_PREFIX = Buffer.from("BAP1-REQUEST\0", "ascii");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const DEFAULT_HASH = Buffer.alloc(32);

// The fixed v1 profile maxima (re-implemented from bounds.ex; pinned by bounds.new
// cases so any mistyped constant fails the corpus). Fixed-width keys MUST equal the
// maximum exactly (widening is forbidden); all others must be a positive integer
// at most the maximum.
const MAXIMA = {
  compact_bytes: 65536,
  encoded_segment_bytes: 32768,
  decoded_segment_bytes: 24576,
  json_bytes: 65536,
  depth: 32,
  object_members: 64,
  array_items: 256,
  total_nodes: 4096,
  string_bytes: 8192,
  key_bytes: 128,
  number_lexeme_bytes: 64,
  integer_magnitude: 9007199254740991,
  float_magnitude: 9007199254740991,
  kid_bytes: 128,
  jcs_bytes: 65536,
  uri_bytes: 8192,
  identifier_bytes: 512,
  nonce_bytes: 512,
  method_bytes: 32,
  operation_bytes: 128,
  audiences: 64,
  operations: 64,
  selectors: 64,
  path_segments: 32,
  one_of_values: 256,
  public_key_bytes: 32,
  signature_bytes: 64,
  digest_bytes: 32,
  clock_skew: 60,
  proof_max_age: 300,
  chain_row_bytes: 4096,
  chain_rows: 65536,
  anchor_bytes: 8192,
  archive_header_bytes: 8192,
  archive_chunks: 65796,
  archive_bytes: 270820384,
  object_version_bytes: 512,
  key_transitions: 256,
};
const FIXED_WIDTH_KEYS = new Set(["digest_bytes", "public_key_bytes", "signature_bytes"]);

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const importedPublicKeyFingerprints = new Set();
// Two-boundary census (design C2): `importedPublicKeyFingerprints` is the discovery-membership set
// (every key the fixtures carry). `verificationImportedFingerprints` is the SEPARATE truth set —
// only keys the runner actually fed to node:crypto createPublicKey on a verification surface. The
// verification-import assertion (main) proves the runner genuinely imported the verification keys,
// which the membership census alone cannot (finding 4b: a discovery-only census stays green even if
// nothing is ever imported). Producer-only keys never reach createPublicKey and are naturally exempt.
const verificationImportedFingerprints = new Set();

// --- error + assertion discipline (mirrors chain_archive_independent.mjs) ----

// A GENUINE protocol rejection (the runner's own validation saying "this input is invalid") is a
// distinct type from a runner BUG (a TypeError/ReferenceError/RangeError, or an uncaught library
// throw). Only InvalidError maps to the corpus INVALID verdict; every other throw aborts the run
// nonzero. This is a whitelist, not an error-type blacklist: a blacklist both false-REDs (a genuine
// invalid_encoding case whose bytes make JSON.parse throw SyntaxError would abort a legitimate
// rejection) and false-GREENs (a plain Error from a runner bug is swallowed to agreement).
class InvalidError extends Error {}

function fail(message) {
  throw new InvalidError(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

// Parse a scanned JSON string literal via JSON.parse, converting a SyntaxError on genuinely-invalid
// bytes (a bad escape in an invalid_encoding case) into an InvalidError protocol rejection — never
// an uncaught SyntaxError that would abort the run under the InvalidError whitelist.
function parseJsonStringLiteral(literal, context) {
  try {
    return JSON.parse(literal);
  } catch {
    return fail(`${context}: invalid string literal`);
  }
}

function exactKeys(value, keys, context) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${context}: object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
    `${context}: closed members`,
  );
}

// --- canonical JSON (JCS: sorted keys, integer/float rules) -----------------

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    // JCS number serialization: safe integers emit as integers; finite floats
    // emit via their JSON form. Non-finite values are non-JSON and rejected.
    assert(Number.isFinite(value), "JCS finite number");
    return Number.isInteger(value) && Number.isSafeInteger(value)
      ? String(value)
      : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  assert(value && typeof value === "object", "JCS value");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

// --- strict base64url (canonical, no pad) -----------------------------------

function strictB64(value, width = undefined) {
  assert(typeof value === "string" && /^[A-Za-z0-9_-]*$/.test(value), "strict base64url alphabet");
  assert(!value.includes("="), "strict base64url padding");
  const decoded = Buffer.from(value, "base64url");
  assert(decoded.toString("base64url") === value, "strict base64url canonical");
  if (width !== undefined) assert(decoded.length === width, `strict base64url width ${width}`);
  return decoded;
}

// Lenient base64url decode (for trusted corpus bytes / corpus-input extraction
// that mirrors the runner's decode_b64_value, which uses Erlang's
// Base.url_decode64 accepting any valid base64url). Used only on case-input
// fields, never on verdict-bearing wire bytes.
function decodeB64Loose(value, context) {
  assert(typeof value === "string", `${context}: base64url string`);
  try {
    return Buffer.from(value, "base64url");
  } catch {
    return null;
  }
}

function isCanonicalBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value) || value.includes("=")) {
    return false;
  }
  const decoded = Buffer.from(value, "base64url");
  return decoded.toString("base64url") === value;
}

// --- SHA-256 ----------------------------------------------------------------

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

// --- duplicate-rejecting JSON parser (strict, mirrors siblings) ------------

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
        return parseJsonStringLiteral(text.slice(start, index), `${context}: string literal`);
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
    while (text.length) {
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
    while (text.length) {
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

function parseCanonicalJson(bytes, context) {
  const text = bytes.toString("utf8");
  assert(Buffer.from(text, "utf8").equals(bytes), `${context}: UTF-8`);
  const value = parseJsonNoDuplicates(text, context);
  assert(canonical(value) === text, `${context}: canonical bytes`);
  return value;
}

function readJsonFile(path, context) {
  return parseJsonNoDuplicates(readFileSync(path, "utf8"), context);
}

// --- Ed25519 public key + RFC 7638 thumbprint (import boundary) ------------

function fingerprint(publicKey) {
  const jwk = { crv: "Ed25519", kty: "OKP", x: publicKey.toString("base64url") };
  return sha256(Buffer.from(canonical(jwk), "utf8"));
}

// Census discovery: fingerprint every public-key-labeled field in the corpus case data, mirroring
// the bap03 discovery model (isPublicKeyLabel: any *public_key*/holder_public_key/etc. field
// holding a 32-byte base64url). This makes the runner's observed import-boundary set equal the
// corpus's FULL declared key set — including invalid_key cases' wrong keys, which the runner reads
// from case data even though their Ed25519 verification fails. Without this, the observed set
// (only keys fed to node:crypto verify) would undercount the declared set.
const PUBLIC_KEY_LABEL = /public.*key|key.*public|verification.*key|holder.*key|issuer.*key/i;
const PUBLIC_KEY_DENY = /fingerprint|thumbprint|digest|hash/i;

function isCensusKeyLabel(key) {
  if (PUBLIC_KEY_DENY.test(key)) return false;
  return PUBLIC_KEY_LABEL.test(key) || ["raw_base64url", "raw_hex", "raw_bytes"].includes(key);
}

function decodeCensusRawKey(value) {
  if (typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value)) {
    const bytes = Buffer.from(value, "base64url");
    return bytes.length === 32 ? bytes : null;
  }
  return null;
}

function collectCaseKeys(value, target) {
  if (Array.isArray(value)) {
    for (const item of value) collectCaseKeys(item, target);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (isCensusKeyLabel(key)) {
      const raw = decodeCensusRawKey(child);
      if (raw) target.add(fingerprint(raw).toString("base64url"));
    }
    collectCaseKeys(child, target);
  }
}

function discoverCaseKeys(value) {
  collectCaseKeys(value, importedPublicKeyFingerprints);
}

function nodePublicKey(raw, context) {
  assert(Buffer.isBuffer(raw) && raw.length === 32, `${context}: Ed25519 public-key width`);
  const fp = fingerprint(raw).toString("base64url");
  importedPublicKeyFingerprints.add(fp);
  verificationImportedFingerprints.add(fp);
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

// --- JCS encode (canonical JSON serializer; the facade's one canonicalizer) -

function jcsEncode(value) {
  // Numbers: integers emit as integers; floats must be representable. The facade
  // rejects non-finite and non-safe-integer magnitudes; mirror that.
  return canonical(value);
}

// --- JSON decode (bounded; mirrors V1.Json.decode semantics) ---------------

// The bounded decoder rejects: non-UTF8, duplicate members, trailing bytes,
// depth > 32, object members > 64, array items > 256, total nodes > 4096,
// string bytes > 8192, number lexeme bytes > 64, raw bytes > 65536,
// integer/float magnitude > 2^53-1. We enforce the structural and magnitude
// rules that the corpus exercises; an exact re-implementation of every internal
// counter is not required for agreement (the corpus cases target the observable
// rejection classes), but the rules below cover every case class present.
function jsonDecode(bytes, context) {
  assert(Buffer.isBuffer(bytes), `${context}: bytes`);
  assert(bytes.length <= 65536, `${context}: json byte bound`);
  const text = bytes.toString("utf8");
  assert(Buffer.from(text, "utf8").equals(bytes), `${context}: UTF-8`);

  let index = 0;
  let nodes = 0;

  function skipWhitespace() {
    while (index < text.length && /[\t\n\r ]/.test(text[index])) index += 1;
  }

  function Err(message) {
    // A malformed-JSON rejection is a protocol INVALID, not a runner bug — InvalidError so the
    // dispatch whitelist maps it to INVALID rather than aborting the run.
    return new InvalidError(`${context}: ${message}`);
  }

  function countNode() {
    nodes += 1;
    assert(nodes <= 4096, "json node bound");
  }

  function decodeString() {
    assert(text[index] === '"', "json string");
    const start = index;
    index += 1;
    while (index < text.length) {
      const ch = text.charCodeAt(index);
      if (ch === 0x5c) {
        // backslash escape
        assert(index + 1 < text.length, "json escape");
        const esc = text[index + 1];
        if (esc === "u") {
          assert(index + 5 < text.length, "json unicode escape");
          index += 6;
        } else {
          index += 2;
        }
        continue;
      }
      if (ch === 0x22) {
        // closing quote — the string byte bound applies to the DECODED value's UTF-8 bytes
        // (excluding the quotes and un-escaped), matching V1.Json's string_bytes ceiling.
        index += 1;
        const parsed = parseJsonStringLiteral(text.slice(start, index), "json string literal");
        assert(Buffer.byteLength(parsed, "utf8") <= 8192, "json string byte bound");
        countNode();
        return parsed;
      }
      index += 1;
    }
    throw Err("json unterminated string");
  }

  function decodeNumber() {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(index));
    if (match === null) throw Err("json number");
    const lexeme = match[0];
    assert(lexeme.length <= 64, "json number lexeme bound");
    index += lexeme.length;
    assert(index === text.length || /[\t\n\r ,\]}]/.test(text[index]), "json number terminator");
    const value = Number(lexeme);
    assert(Number.isFinite(value), "json finite number");
    if (Number.isInteger(value)) {
      assert(Math.abs(value) <= 9007199254740991, "json integer magnitude");
    } else {
      assert(Math.abs(value) <= 9007199254740991, "json float magnitude");
    }
    countNode();
    return value;
  }

  function decodeValue(depth) {
    assert(depth <= 32, "json depth bound");
    skipWhitespace();
    assert(index < text.length, "json value");
    const ch = text[index];
    if (ch === "{") return decodeObject(depth + 1);
    if (ch === "[") return decodeArray(depth + 1);
    if (ch === '"') return decodeString();
    if (text.startsWith("true", index)) {
      index += 4;
      countNode();
      return true;
    }
    if (text.startsWith("false", index)) {
      index += 5;
      countNode();
      return false;
    }
    if (text.startsWith("null", index)) {
      index += 4;
      countNode();
      return null;
    }
    return decodeNumber();
  }

  function decodeObject(depth) {
    const names = new Set();
    const value = Object.create(null);
    index += 1;
    countNode();
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return value;
    }
    while (text.length) {
      skipWhitespace();
      const name = decodeString();
      // Object-name byte ceiling (128) — distinct from the 8192 string-value ceiling decodeString
      // enforces; the profile bounds object names at 128 bytes (bounds.ex key_bytes).
      assert(Buffer.byteLength(name, "utf8") <= 128, "json object-name byte bound");
      assert(!names.has(name), `json duplicate member ${name}`);
      names.add(name);
      assert(names.size <= 64, "json member bound");
      skipWhitespace();
      assert(text[index] === ":", "json member separator");
      index += 1;
      value[name] = decodeValue(depth);
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return value;
      }
      assert(text[index] === ",", "json object separator");
      index += 1;
    }
    throw Err("json unterminated object");
  }

  function decodeArray(depth) {
    const value = [];
    index += 1;
    countNode();
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return value;
    }
    while (text.length) {
      value.push(decodeValue(depth));
      assert(value.length <= 256, "json array bound");
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return value;
      }
      assert(text[index] === ",", "json array separator");
      index += 1;
    }
    throw Err("json unterminated array");
  }

  const value = decodeValue(1);
  skipWhitespace();
  assert(index === text.length, "json trailing bytes");
  return value;
}

// --- URI normalize (RFC 3986 §6, https-only; mirrors V1.Uri) ---------------

function isCanonicalIpv4(host) {
  const octets = host.split(".");
  return (
    octets.length === 4 &&
    octets.every((octet) => /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255)
  );
}

function assertRegName(host) {
  for (let i = 0; i < host.length; i += 1) {
    const ch = host[i];
    if (/[A-Za-z0-9\-._~!$&'()*+,;=]/.test(ch)) continue;
    assert(
      ch === "%" && i + 2 < host.length && /^[0-9A-Fa-f]{2}$/.test(host.slice(i + 1, i + 3)),
      "uri reg-name",
    );
    i += 2;
  }
}

function normalizePercentEncoding(value) {
  let result = "";
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] !== "%") {
      result += value[i];
      continue;
    }
    assert(i + 2 < value.length && /^[0-9A-Fa-f]{2}$/.test(value.slice(i + 1, i + 3)), "uri escape");
    const octet = Number.parseInt(value.slice(i + 1, i + 3), 16);
    const ch = String.fromCharCode(octet);
    result += /[A-Za-z0-9\-._~]/.test(ch)
      ? ch
      : `%${octet.toString(16).toUpperCase().padStart(2, "0")}`;
    i += 2;
  }
  return result;
}

function lowercaseOutsideEscapes(value) {
  let result = "";
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] === "%") {
      result += value.slice(i, i + 3);
      i += 2;
    } else {
      result += value[i].toLowerCase();
    }
  }
  return result;
}

function removeDotSegments(path) {
  let input = path;
  let output = "";
  while (input.length > 0) {
    if (input.startsWith("../")) input = input.slice(3);
    else if (input.startsWith("./")) input = input.slice(2);
    else if (input.startsWith("/./")) input = input.slice(2);
    else if (input === "/.") input = "/";
    else if (input.startsWith("/../")) {
      input = input.slice(3);
      output = output.replace(/\/?[^/]*$/, "");
    } else if (input === "/..") {
      input = "/";
      output = output.replace(/\/?[^/]*$/, "");
    } else if (input === "." || input === "..") input = "";
    else {
      const nextSlash = input.indexOf("/", input.startsWith("/") ? 1 : 0);
      const end = nextSlash === -1 ? input.length : nextSlash;
      output += input.slice(0, end);
      input = input.slice(end);
    }
  }
  return output;
}

function ipv6Kind(literal) {
  // Returns 6 = valid IPv6, "future" = IPvFuture, null = invalid.
  if (/^[0-9A-Fa-f:.]+$/.test(literal)) {
    // crude hex-colon validation; rely on node:net for authority.
    return 6;
  }
  if (/^v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/.test(literal)) return "future";
  return null;
}

function normalizeHttpsUri(bytes, context) {
  assert(Buffer.isBuffer(bytes), `${context}: bytes`);
  assert(bytes.length <= 8192, `${context}: uri byte bound`);
  const uri = bytes.toString("utf8");
  assert(Buffer.from(uri, "utf8").equals(bytes), `${context}: UTF-8`);
  assert(/^[\x21-\x7E]+$/.test(uri), `${context}: URI ASCII`);
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)$/.exec(uri);
  assert(match !== null, `${context}: URI hierarchical shape`);
  assert(match[1].toLowerCase() === "https", `${context}: URI scheme`);

  const authority = match[2];
  assert(authority.length > 0 && !authority.includes("@"), `${context}: URI authority`);
  let host;
  let port = "";

  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    assert(close > 1, `${context}: URI IPv6 host`);
    const literal = authority.slice(1, close);
    const kind = ipv6Kind(literal);
    assert(kind !== null, `${context}: URI IP-literal syntax`);
    host = kind === "future" ? `[${literal}]` : `[${literal.toLowerCase()}]`;
    const suffix = authority.slice(close + 1);
    assert(suffix === "" || /^:\d+$/.test(suffix), `${context}: URI IPv6 port`);
    port = suffix.slice(1);
  } else {
    assert((authority.match(/:/g) ?? []).length <= 1, `${context}: URI host/port ambiguity`);
    const separator = authority.lastIndexOf(":");
    if (separator >= 0) {
      host = authority.slice(0, separator);
      port = authority.slice(separator + 1);
      assert(port.length > 0, `${context}: URI empty port`);
    } else {
      host = authority;
    }
    assert(host.length > 0, `${context}: URI host`);
    if (/^[0-9.]+$/.test(host)) {
      assert(isCanonicalIpv4(host), `${context}: URI IPv4 syntax`);
    } else {
      assertRegName(host);
      host = lowercaseOutsideEscapes(normalizePercentEncoding(host));
    }
  }

  if (port !== "") {
    assert(/^\d+$/.test(port), `${context}: URI port`);
    const portNumber = Number(port);
    assert(portNumber >= 1 && portNumber <= 65535, `${context}: URI port range`);
    port = portNumber === 443 ? "" : `:${portNumber}`;
  }

  const normalizedPath = removeDotSegments(
    normalizePercentEncoding(match[3] === "" ? "/" : match[3]),
  );
  assert(normalizedPath.startsWith("/"), `${context}: URI absolute path`);
  return `https://${host}${port}${normalizedPath}`;
}

// --- chain/archive framing (independent re-implementation) -----------------

function frame(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
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
  for (let i = 0; i < header.transition_count; i += 1) {
    const f = readFrame(bytes, cursor, 8192, `transition ${i}`);
    transitionFrames.push(f.bytes);
    cursor = f.next;
  }
  const rowFrames = [];
  for (let i = 0; i < header.row_count; i += 1) {
    const f = readFrame(bytes, cursor, 4096, `row ${i}`);
    rowFrames.push(f.bytes);
    cursor = f.next;
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

// --- compact JWS parse + verify (protected.payload.signature) ---------------

function parseCompactJws(compact, context) {
  assert(typeof compact === "string" && compact.length <= 65536, `${context}: compact size`);
  const segments = compact.split(".");
  assert(segments.length === 3, `${context}: compact shape`);
  return {
    protectedSegment: segments[0],
    payloadSegment: segments[1],
    signatureSegment: segments[2],
    protectedBytes: strictB64(segments[0]),
    payloadBytes: strictB64(segments[1]),
    signature: strictB64(segments[2]),
    message: Buffer.from(`${segments[0]}.${segments[1]}`, "ascii"),
  };
}

function verifyEd25519(publicKey, message, signature) {
  return verifySignature(null, message, publicKey, signature);
}

// --- bounds.new (independent tightening-only validation) -------------------

function boundsNew(overrides, context) {
  assert(overrides && typeof overrides === "object" && !Array.isArray(overrides), `${context}: map`);
  for (const [key, value] of Object.entries(overrides)) {
    const maximum = MAXIMA[key];
    if (maximum === undefined) return false;
    if (FIXED_WIDTH_KEYS.has(key)) {
      if (value !== maximum) return false;
    } else if (!(Number.isInteger(value) && value > 0 && value <= maximum)) {
      return false;
    }
  }
  return true;
}

// ===========================================================================
// Corpus loading + integrity (mirrors Corpus.load/1)
// ===========================================================================

const EXPECTED_CLASSES = [
  "valid",
  "boundary_near",
  "exact_bound",
  "maximum_plus_one",
  "invalid_duplicate",
  "invalid_encoding",
  "invalid_algorithm",
  "invalid_key",
  "invalid_claim",
  "invalid_time",
  "invalid_nonce",
  "invalid_uri",
  "invalid_request",
  "invalid_selector",
  "invalid_limit",
  "tamper_meaningful_byte",
];

function listCorpusFiles(corpusDir) {
  const result = [];
  function walk(dir) {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      const info = statSync(path);
      if (info.isDirectory()) walk(path);
      else if (info.isFile()) result.push(path);
    }
  }
  walk(corpusDir);
  return result.sort();
}

function loadCorpus(corpusDir) {
  const indexPath = join(corpusDir, "index.json");
  const indexBytes = readFileSync(indexPath);
  const index = parseJsonNoDuplicates(indexBytes.toString("utf8"), `index ${indexPath}`);

  exactKeys(
    index,
    ["format", "public_key_fingerprints", "files", "total_cases", "applicability"],
    "corpus index",
  );
  assert(
    index.format === "bounded-authority-protocol-v1-conformance-corpus-index",
    "corpus index format",
  );
  assert(Array.isArray(index.public_key_fingerprints), "index fingerprints list");
  assert(Array.isArray(index.files), "index files list");
  assert(index.files.length <= 256, "index file count bound");
  assert(Number.isSafeInteger(index.total_cases), "index total_cases integer");

  // Per-file SHA-256 + hash-bind the raw sidecars. Build the declared file map
  // keyed by repo-relative path (relative to corpus dir).
  const declaredFiles = new Map();
  let declaredCaseTotal = 0;
  for (const entry of index.files) {
    exactKeys(entry, ["path", "sha256_base64url", "cases"], "index file entry");
    assert(typeof entry.path === "string" && entry.path.length > 0, "index file path");
    assert(!declaredFiles.has(entry.path), `index duplicate file ${entry.path}`);
    const digest = strictB64(entry.sha256_base64url, 32);
    assert(Number.isInteger(entry.cases) && entry.cases >= 0, `index file cases ${entry.path}`);
    declaredFiles.set(entry.path, { digest, cases: entry.cases });
    declaredCaseTotal += entry.cases;
  }
  assert(declaredCaseTotal === index.total_cases, "index total_cases sum");

  // Observed files on disk (relative to corpus dir), both directions equality.
  // `index.json` is the integrity binding itself, not a case file — it is the
  // one file outside the `files` list by design.
  const observedRelPaths = new Set();
  const fileBytes = new Map(); // rel path -> Buffer
  for (const absPath of listCorpusFiles(corpusDir)) {
    const rel = relative(corpusDir, absPath);
    if (rel === "index.json") continue;
    observedRelPaths.add(rel);
    fileBytes.set(rel, readFileSync(absPath));
  }
  const declaredRelPaths = new Set(declaredFiles.keys());
  for (const rel of declaredRelPaths) {
    assert(observedRelPaths.has(rel), `corpus missing declared file ${rel}`);
  }
  for (const rel of observedRelPaths) {
    assert(declaredRelPaths.has(rel), `corpus undeclared file ${rel}`);
  }

  // Recompute per-file SHA-256 and bind raw sidecar hashes.
  for (const [rel, bytes] of fileBytes) {
    const { digest } = declaredFiles.get(rel);
    equalBytes(sha256(bytes), digest, `index file hash ${rel}`);
  }

  // Decode every JSON case file with the bounded decoder (normative load path).
  // `.raw` sidecars are hash-bound above and never parsed.
  const cases = []; // flat list of {case, fileRel, raws}
  const caseIds = new Set();
  for (const [rel, bytes] of fileBytes) {
    if (extname(rel) !== ".json") continue;
    const fileCases = parseJsonNoDuplicates(
      bytes.toString("utf8"),
      `case file ${rel}`,
    );
    assert(Buffer.from(JSON.stringify(fileCases).slice(0, 0)).length === 0, "noop");
    assert(
      fileCases.format === "bounded-authority-protocol-v1-conformance-cases",
      `${rel}: case file format`,
    );
    assert(fileCases.provenance.private_material_tracked === false, `${rel}: provenance`);
    assert(Array.isArray(fileCases.cases), `${rel}: cases array`);
    // Verify the declared case count matches the executed count.
    const declared = declaredFiles.get(rel).cases;
    assert(fileCases.cases.length === declared, `${rel}: case count ${fileCases.cases.length} vs ${declared}`);
    for (const c of fileCases.cases) {
      assert(typeof c.id === "string" && c.id.length > 0, `${rel}: case id`);
      assert(!caseIds.has(c.id), `corpus duplicate case id ${c.id}`);
      caseIds.add(c.id);
      assert(typeof c.surface === "string", `${c.id}: surface`);
      assert(typeof c.class === "string", `${c.id}: class`);
      assert(c.expected && typeof c.expected === "object", `${c.id}: expected`);
      // Census: fingerprint every public-key field in this case's data (mirrors the bap03
      // discovery model) so the observed import-boundary set equals the corpus's declared set.
      discoverCaseKeys(c);
      cases.push({ caseObj: c, fileRel: rel });
    }
  }
  assert(cases.length === index.total_cases, "corpus executed case count");

  // Applicability matrix: totally classified, both directions.
  assert(
    index.applicability && typeof index.applicability === "object",
    "index applicability object",
  );
  const observedMatrix = {}; // surface -> class -> executed count
  for (const { caseObj } of cases) {
    if (!observedMatrix[caseObj.surface]) observedMatrix[caseObj.surface] = {};
    const cell = observedMatrix[caseObj.surface];
    cell[caseObj.class] = (cell[caseObj.class] ?? 0) + 1;
  }
  for (const [surface, classes] of Object.entries(index.applicability)) {
    assert(classes && typeof classes === "object", `applicability ${surface}: object`);
    const observedClasses = Object.keys(classes).sort();
    assert(
      JSON.stringify(observedClasses) === JSON.stringify([...EXPECTED_CLASSES].sort()),
      `applicability ${surface}: closed class members`,
    );
    const executed = observedMatrix[surface] ?? {};
    for (const [cls, declared] of Object.entries(classes)) {
      // An applicability leaf may be a bare "n_a" string OR an object {"n_a": "<reason>"}. The
      // object form carries a falsifiable reason (Q29 obligation) for human review; both are
      // treated identically by the machine check (not-applicable: zero executed cases).
      const isNotApplicable = declared === "n_a" || (declared && typeof declared === "object" && typeof declared.n_a === "string");
      if (isNotApplicable) {
        assert((executed[cls] ?? 0) === 0, `applicability ${surface}/${cls}: n_a cell populated`);
      } else {
        assert(Number.isInteger(declared) && declared >= 1, `applicability ${surface}/${cls}: count`);
        assert(
          (executed[cls] ?? 0) === declared,
          `applicability ${surface}/${cls}: declared ${declared} executed ${executed[cls] ?? 0}`,
        );
      }
    }
  }
  // Reverse direction: every executed cell must be declared (n/a or matching count).
  for (const [surface, classes] of Object.entries(observedMatrix)) {
    for (const cls of Object.keys(classes)) {
      assert(
        index.applicability[surface] !== undefined &&
          index.applicability[surface][cls] !== undefined,
        `applicability ${surface}/${cls}: executed cell not declared`,
      );
    }
  }

  // Resolve `.raw` sidecars for case inputs and bind their case-local hash.
  const raws = new Map(); // rel path -> Buffer
  for (const { caseObj } of cases) {
    const input = caseObj.input || {};
    if (typeof input.raw_file === "string") {
      const rel = input.raw_file;
      assert(declaredFiles.has(rel), `${caseObj.id}: raw_file declared ${rel}`);
      let bytes = raws.get(rel);
      if (bytes === undefined) {
        bytes = fileBytes.get(rel);
        assert(Buffer.isBuffer(bytes), `${caseObj.id}: raw bytes present`);
        raws.set(rel, bytes);
      }
      assert(
        typeof input.sha256_base64url === "string",
        `${caseObj.id}: raw_file hash present`,
      );
      equalBytes(sha256(bytes), strictB64(input.sha256_base64url, 32), `${caseObj.id}: raw_file hash`);
    }
  }

  // Tamper verbatim-vs-derived audit (mirrors the official loader; a mismatch aborts the run).
  verifyTampers(cases);

  return { index, cases, raws, corpusDir };
}

// ===========================================================================
// Input extraction (mirrors runner.ex helpers)
// ===========================================================================

function inputBytes(input, raws, context) {
  if (typeof input.text === "string") return Buffer.from(input.text, "utf8");
  if (typeof input.base64url === "string") {
    const decoded = decodeB64Loose(input.base64url, context);
    if (decoded === null) fail(`${context}: invalid base64url`);
    return decoded;
  }
  if (typeof input.raw_file === "string") {
    const bytes = raws.get(input.raw_file);
    if (!Buffer.isBuffer(bytes)) fail(`${context}: missing raw_file`);
    return bytes;
  }
  fail(`${context}: no input bytes`);
}

function fetchBinary(input, key, context) {
  const value = input[key];
  if (typeof value !== "string") fail(`${context}: missing ${key}`);
  return value;
}

function b64Field(input, key, context) {
  const encoded = fetchBinary(input, key, context);
  const decoded = decodeB64Loose(encoded, context);
  if (decoded === null) fail(`${context}: invalid ${key}`);
  return decoded;
}

function intField(input, key, context) {
  const value = input[key];
  if (!Number.isSafeInteger(value)) fail(`${context}: integer ${key}`);
  return value;
}

function inputPublicKey(input, context) {
  const encoded = fetchBinary(input, "public_key", context);
  const decoded = decodeB64Loose(encoded, context);
  if (decoded === null) fail(`${context}: invalid public_key`);
  return decoded;
}

function stringList(input, key, context) {
  const list = input[key];
  if (!Array.isArray(list) || list.length === 0) fail(`${context}: list ${key}`);
  for (const item of list) {
    if (typeof item !== "string") fail(`${context}: string item ${key}`);
  }
  return list;
}

function byteList(input, key, context) {
  const list = input[key];
  if (!Array.isArray(list)) fail(`${context}: list ${key}`);
  return list.map((item, i) => {
    if (typeof item !== "string") fail(`${context}: ${key}[${i}]`);
    const decoded = decodeB64Loose(item, context);
    if (decoded === null) fail(`${context}: ${key}[${i}] invalid`);
    return decoded;
  });
}

// --- tamper verbatim-vs-derived audit (Q25) --------------------------------
// The independent second implementation of Corpus.verify_tampers: re-derive base-with-one-flip
// on the addressed target and require byte-equality with the tampered case's stored verbatim
// artifact, so a tamper case that labels a flip it did not actually perform is rejected at load.
// Target resolution mirrors corpus.ex tamper_target_bytes/2 (default/text/base64url +
// compact/grant/proof/rows[i]/chunks[i]).

function tamperB64(encoded, context) {
  const decoded = decodeB64Loose(encoded, context);
  if (decoded === null) fail(`${context}: invalid base64url`);
  // Canonical/strict check: the loose decode silently drops non-alphabet bytes and tolerates
  // non-canonical pad bits, whereas the official Elixir loader's Base.url_decode64(padding: false)
  // rejects both. Require an exact canonical roundtrip so the tamper audit is a genuine independent
  // MIRROR of the strict loader on the rows[i]/chunks[i]/base64url targets (cross-vendor GLM note).
  if (decoded.toString("base64url") !== encoded) fail(`${context}: non-canonical base64url`);
  return decoded;
}

function tamperTargetBytes(caseObj, target, context) {
  const input = caseObj.input || {};
  switch (target) {
    case undefined:
      if (typeof input.text === "string") return Buffer.from(input.text, "utf8");
      if (typeof input.base64url === "string") return tamperB64(input.base64url, context);
      break;
    case "input.text":
      if (typeof input.text === "string") return Buffer.from(input.text, "utf8");
      break;
    case "input.base64url":
      if (typeof input.base64url === "string") return tamperB64(input.base64url, context);
      break;
    case "compact":
      if (typeof input.compact === "string") return Buffer.from(input.compact, "utf8");
      break;
    case "grant":
      if (typeof input.grant === "string") return Buffer.from(input.grant, "utf8");
      break;
    case "proof":
      if (typeof input.proof === "string") return Buffer.from(input.proof, "utf8");
      break;
    default: {
      const m = /^(rows|chunks)\[(\d+)\]$/.exec(target);
      if (m) {
        const list = input[m[1]];
        const i = Number(m[2]);
        if (Array.isArray(list) && typeof list[i] === "string") return tamperB64(list[i], context);
      }
    }
  }
  return fail(`${context}: unresolved tamper target ${target}`);
}

function verifyTampers(cases) {
  const byId = new Map();
  for (const { caseObj } of cases) byId.set(caseObj.id, caseObj);
  for (const { caseObj } of cases) {
    const tamper = caseObj.tamper;
    if (!tamper || typeof tamper !== "object") continue;
    assert(typeof tamper.base_case === "string", `${caseObj.id}: tamper base_case`);
    assert(
      Number.isInteger(tamper.byte_index) && tamper.byte_index >= 0,
      `${caseObj.id}: tamper byte_index`,
    );
    assert(Number.isInteger(tamper.xor), `${caseObj.id}: tamper xor`);
    const base = byId.get(tamper.base_case);
    assert(base !== undefined, `${caseObj.id}: tamper base_case ${tamper.base_case} present`);
    const baseBytes = tamperTargetBytes(base, tamper.target, `${caseObj.id} tamper base`);
    const verbatim = tamperTargetBytes(caseObj, tamper.target, `${caseObj.id} tamper verbatim`);
    assert(tamper.byte_index < baseBytes.length, `${caseObj.id}: tamper byte_index in range`);
    const derived = Buffer.from(baseBytes);
    derived[tamper.byte_index] = derived[tamper.byte_index] ^ (tamper.xor & 0xff);
    assert(
      derived.equals(verbatim),
      `${caseObj.id}: tamper verbatim != derived (target ${tamper.target})`,
    );
  }
}

// ===========================================================================
// Verdict agreement
// ===========================================================================

const INVALID = Symbol("invalid");

function agree(expected, actual) {
  if (expected.verdict === "invalid") return actual === INVALID;
  if (expected.verdict === "valid") {
    if (actual === INVALID) return false;
    // Every expected field (besides verdict) must match the projected actual.
    for (const [key, expectedValue] of Object.entries(expected)) {
      if (key === "verdict") continue;
      const actualValue = actual[key];
      if (!compareField(key, expectedValue, actualValue)) return false;
    }
    return true;
  }
  return false;
}

function compareField(key, expected, actual) {
  if (actual === undefined) return false;
  // value: structural JSON equality (canonical comparison).
  if (key === "value" || key === "decoded") {
    return canonical(expected) === canonical(actual);
  }
  // bounds: structural equality of the resolved tightened overrides (no longer presence-only).
  if (key === "bounds") return canonical(expected) === canonical(actual);
  // String fields: byte-wise; expected may be a raw string.
  if (typeof expected === "string" && typeof actual === "string") {
    return expected === actual;
  }
  // Number/boolean equality.
  return Object.is(expected, actual);
}

// ===========================================================================
// Surface dispatch — independent recompute of each verdict
// ===========================================================================

function dispatch(surface, input, raws) {
  switch (surface) {
    case "json.decode":
      return dispatchJsonDecode(input, raws);
    case "base64url.decode":
      return dispatchBase64UrlDecode(input);
    case "jcs.encode":
      return dispatchJcsEncode(input, raws);
    case "uri.normalize":
      return dispatchUriNormalize(input, raws);
    case "jwk.encode_public":
      return dispatchJwkEncodePublic(input);
    case "jwk.decode_public":
      return dispatchJwkDecodePublic(input, raws);
    case "jwk.thumbprint_preimage":
      return dispatchJwkThumbprintPreimage(input, raws);
    case "jwk.thumbprint":
      return dispatchJwkThumbprint(input, raws);
    case "jwk.thumbprint_raw":
      return dispatchJwkThumbprintRaw(input, raws);
    case "jwk.public_key_thumbprint_raw":
      return dispatchJwkPublicKeyThumbprintRaw(input);
    case "bounds.new":
      return dispatchBoundsNew(input);
    case "untrusted_key_locator":
      return dispatchUntrustedKeyLocator(input);
    case "grant_signing_input":
      return dispatchGrantSigningInput(input);
    case "proof_signing_input":
      return dispatchProofSigningInput(input);
    case "boundary_anchor_signing_input":
      return dispatchBoundaryAnchorSigningInput(input);
    case "key_transition_signing_input":
      return dispatchKeyTransitionSigningInput(input);
    case "assemble_compact":
      return dispatchAssembleCompact(input);
    case "decode_grant":
      return dispatchDecodeGrant(input);
    case "decode_proof":
      return dispatchDecodeProof(input);
    case "encode_consumption_entry":
      return dispatchEncodeConsumptionEntry(input);
    case "check_chain":
      return dispatchCheckChain(input);
    case "request_digest":
      return dispatchRequestDigest(input);
    case "verify_grant":
      return dispatchVerifyGrant(input);
    case "verify_historical_anchor":
      return dispatchVerifyHistoricalAnchor(input);
    case "verify_key_transition":
      return dispatchVerifyKeyTransition(input);
    case "check_envelope":
      return dispatchCheckEnvelope(input);
    case "encode_anchored_export":
      return dispatchEncodeAnchoredExport(input);
    case "verify_anchored_export":
      return dispatchVerifyAnchoredExport(input);
    default:
      throw new Error(`unknown surface ${surface}`);
  }
}

// --- decode surfaces --------------------------------------------------------

function dispatchJsonDecode(input, raws) {
  const bytes = inputBytes(input, raws, "json.decode");
  const value = jsonDecode(bytes, "json.decode");
  return { value };
}

function dispatchBase64UrlDecode(input) {
  let segment;
  if (typeof input.base64url === "string") {
    segment = input.base64url;
  } else {
    // Fallback: derive the segment from input bytes (text/base64url/raw).
    segment = inputBytes(input, new Map(), "base64url.decode").toString("utf8");
  }
  if (segment.length === 0) fail("base64url.decode: empty segment");
  if (!isCanonicalBase64Url(segment)) fail("base64url.decode: non-canonical");
  return { decoded: Buffer.from(segment, "base64url").toString("utf8") };
}

function dispatchJcsEncode(input, raws) {
  const bytes = inputBytes(input, raws, "jcs.encode");
  const value = jsonDecode(bytes, "jcs.encode");
  const encoded = jcsEncode(value);
  return { encoded };
}

function dispatchUriNormalize(input, raws) {
  const bytes = inputBytes(input, raws, "uri.normalize");
  const normalized = normalizeHttpsUri(bytes, "uri.normalize");
  return { normalized };
}

// --- JWK surfaces -----------------------------------------------------------

function exactPublicJwk(value, context) {
  exactKeys(value, ["crv", "kty", "x"], context);
  assert(value.crv === "Ed25519", `${context}: curve`);
  assert(value.kty === "OKP", `${context}: type`);
  const x = strictB64(value.x, 32);
  return { crv: value.crv, kty: value.kty, x: value.x, raw: x };
}

function jwkFromPublicKey(raw) {
  return { crv: "Ed25519", kty: "OKP", x: raw.toString("base64url") };
}

function jwkThumbprintPreimage(jwk) {
  return canonical({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
}

function jwkThumbprint(jwk) {
  return sha256(Buffer.from(jwkThumbprintPreimage(jwk), "utf8")).toString("base64url");
}

function dispatchJwkEncodePublic(input) {
  const raw = inputPublicKey(input, "jwk.encode_public");
  assert(raw.length === 32, "jwk.encode_public: public key width");
  const jwk = jwkFromPublicKey(raw);
  return { encoded: canonical(jwk) };
}

function dispatchJwkDecodePublic(input, raws) {
  const bytes = inputBytes(input, raws, "jwk.decode_public");
  const value = jsonDecode(bytes, "jwk.decode_public");
  const jwk = exactPublicJwk(value, "jwk.decode_public");
  return { public_key: jwk.raw.toString("base64url") };
}

function dispatchJwkThumbprintPreimage(input, raws) {
  const bytes = inputBytes(input, raws, "jwk.thumbprint_preimage");
  const value = jsonDecode(bytes, "jwk.thumbprint_preimage");
  const jwk = exactPublicJwk(value, "jwk.thumbprint_preimage");
  return { preimage: jwkThumbprintPreimage(jwk) };
}

function dispatchJwkThumbprint(input, raws) {
  const bytes = inputBytes(input, raws, "jwk.thumbprint");
  const value = jsonDecode(bytes, "jwk.thumbprint");
  const jwk = exactPublicJwk(value, "jwk.thumbprint");
  return { thumbprint: jwkThumbprint(jwk) };
}

function dispatchJwkThumbprintRaw(input, raws) {
  const bytes = inputBytes(input, raws, "jwk.thumbprint_raw");
  const value = jsonDecode(bytes, "jwk.thumbprint_raw");
  const jwk = exactPublicJwk(value, "jwk.thumbprint_raw");
  // Result is the raw 32-byte digest; the case only checks verdict=valid.
  return { thumbprint_raw: sha256(Buffer.from(jwkThumbprintPreimage(jwk), "utf8")) };
}

function dispatchJwkPublicKeyThumbprintRaw(input) {
  const raw = inputPublicKey(input, "jwk.public_key_thumbprint_raw");
  assert(raw.length === 32, "jwk.public_key_thumbprint_raw: public key width");
  const jwk = jwkFromPublicKey(raw);
  return { thumbprint_raw: sha256(Buffer.from(jwkThumbprintPreimage(jwk), "utf8")) };
}

// --- bounds.new -------------------------------------------------------------

function dispatchBoundsNew(input) {
  const overrides = input.overrides ?? {};
  if (!boundsNew(overrides, "bounds.new")) fail("bounds.new: invalid overrides");
  // Return the RESOLVED tightened overrides so a valid case carrying `expected.bounds` is checked
  // field-by-field (not presence-only). A case with no `expected.bounds` still agrees on verdict.
  return { bounds: overrides };
}

// --- untrusted_key_locator --------------------------------------------------

function dispatchUntrustedKeyLocator(input) {
  const compact = fetchBinary(input, "compact", "untrusted_key_locator");
  const jws = parseCompactJws(compact, "untrusted_key_locator");
  const header = parseCanonicalJson(jws.protectedBytes, "untrusted_key_locator header");
  exactKeys(header, ["alg", "kid", "typ"], "untrusted_key_locator header");
  assert(header.alg === "EdDSA", "untrusted_key_locator alg");
  assert(typeof header.kid === "string" && header.kid.length > 0, "untrusted_key_locator kid");
  return { kid: header.kid };
}

// --- signing-input producers -----------------------------------------------

function buildOperation(op, context) {
  if (!op || typeof op.name !== "string") fail(`${context}: operation name`);
  const selectors = op.selectors;
  if (!Array.isArray(selectors)) fail(`${context}: selectors`);
  return { name: op.name, selectors: selectors.map((s) => buildSelector(s, context)) };
}

function buildSelector(selector, context) {
  // The facade serializes selectors in their object form: {"kind":"all"},
  // {"kind":"equals","path":[...],"value":...}, {"kind":"one_of",...}. The case
  // input may give the "all" selector as the bare string "all" — normalize it.
  if (selector === "all") return { kind: "all" };
  if (selector && selector.kind === "all") return { kind: "all" };
  if (selector && selector.kind === "equals" && Array.isArray(selector.path)) {
    return { kind: "equals", path: selector.path, value: selector.value };
  }
  if (selector && selector.kind === "one_of" && Array.isArray(selector.path) && Array.isArray(selector.values)) {
    return { kind: "one_of", path: selector.path, values: selector.values };
  }
  fail(`${context}: selector shape`);
}

function dispatchGrantSigningInput(input) {
  const keyId = fetchBinary(input, "key_id", "grant_signing_input");
  const issuer = fetchBinary(input, "issuer", "grant_signing_input");
  const grantId = fetchBinary(input, "grant_id", "grant_signing_input");
  const audiences = stringList(input, "audiences", "grant_signing_input");
  const issuedAt = intField(input, "issued_at", "grant_signing_input");
  const notBefore = intField(input, "not_before", "grant_signing_input");
  const expiresAt = intField(input, "expires_at", "grant_signing_input");
  const holderThumbprint = b64Field(input, "holder_thumbprint", "grant_signing_input");
  const operations = input.operations;
  if (!Array.isArray(operations) || operations.length === 0) fail("grant_signing_input: operations");
  const builtOps = operations.map((o) => buildOperation(o, "grant_signing_input"));

  const header = { alg: "EdDSA", kid: keyId, typ: "ba+cap" };
  const payload = {
    aud: audiences,
    cnf: { jkt: holderThumbprint.toString("base64url") },
    exp: expiresAt,
    iat: issuedAt,
    iss: issuer,
    jti: grantId,
    nbf: notBefore,
    operations: builtOps,
    v: 1,
  };
  const protectedSegment = Buffer.from(canonical(header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(canonical(payload), "utf8").toString("base64url");
  return {
    protected_segment: protectedSegment,
    payload_segment: payloadSegment,
    message: `${protectedSegment}.${payloadSegment}`,
  };
}

function dispatchProofSigningInput(input) {
  const holderPublicKey = b64Field(input, "holder_public_key", "proof_signing_input");
  assert(holderPublicKey.length === 32, "proof_signing_input: holder key width");
  const proofId = fetchBinary(input, "proof_id", "proof_signing_input");
  const method = fetchBinary(input, "method", "proof_signing_input");
  const targetUri = fetchBinary(input, "target_uri", "proof_signing_input");
  const issuedAt = intField(input, "issued_at", "proof_signing_input");
  const invocationId = fetchBinary(input, "invocation_id", "proof_signing_input");
  const operation = fetchBinary(input, "operation", "proof_signing_input");
  const grantCompact = fetchBinary(input, "grant_compact", "proof_signing_input");
  const castArguments = input.cast_arguments;
  if (castArguments === undefined) fail("proof_signing_input: cast_arguments");

  // The facade normalizes+validates htu as an https URI before signing.
  normalizeHttpsUri(Buffer.from(targetUri, "utf8"), "proof_signing_input htu");

  const jwk = jwkFromPublicKey(holderPublicKey);
  const header = { alg: "EdDSA", jwk, typ: "dpop+jwt" };
  const payload = {
    ath: sha256(Buffer.from(grantCompact, "ascii")).toString("base64url"),
    ba_inv: invocationId,
    ba_op: operation,
    ba_req: requestDigest(operation, castArguments),
    htm: method,
    htu: targetUri,
    iat: issuedAt,
    jti: proofId,
    v: 1,
  };
  if (input.nonce !== undefined) {
    const nonce = decodeB64Loose(input.nonce, "proof_signing_input");
    if (nonce !== null) payload.nonce = nonce.toString("base64url");
  }
  const protectedSegment = Buffer.from(canonical(header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(canonical(payload), "utf8").toString("base64url");
  return {
    protected_segment: protectedSegment,
    payload_segment: payloadSegment,
    message: `${protectedSegment}.${payloadSegment}`,
  };
}

function dispatchBoundaryAnchorSigningInput(input) {
  const anchorId = fetchBinary(input, "anchor_id", "boundary_anchor_signing_input");
  const anchoredAt = intField(input, "anchored_at", "boundary_anchor_signing_input");
  const chainId = fetchBinary(input, "chain_id", "boundary_anchor_signing_input");
  const sequence = intField(input, "sequence", "boundary_anchor_signing_input");
  const chainHash = b64Field(input, "chain_hash", "boundary_anchor_signing_input");
  const keyId = fetchBinary(input, "key_id", "boundary_anchor_signing_input");
  const publicKey = b64Field(input, "public_key", "boundary_anchor_signing_input");
  assert(publicKey.length === 32, "boundary_anchor_signing_input: public key width");

  const header = { alg: "EdDSA", kid: keyId, typ: "ba+chain-anchor" };
  const payload = {
    anchor_id: anchorId,
    anchored_at: anchoredAt,
    chain_hash: chainHash.toString("base64url"),
    chain_id: chainId,
    key_fingerprint: jwkThumbprint(jwkFromPublicKey(publicKey)),
    sequence,
    v: 1,
  };
  const protectedSegment = Buffer.from(canonical(header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(canonical(payload), "utf8").toString("base64url");
  return {
    protected_segment: protectedSegment,
    payload_segment: payloadSegment,
    message: `${protectedSegment}.${payloadSegment}`,
  };
}

function dispatchKeyTransitionSigningInput(input) {
  const transitionId = fetchBinary(input, "transition_id", "key_transition_signing_input");
  const chainId = fetchBinary(input, "chain_id", "key_transition_signing_input");
  const effectiveAt = intField(input, "effective_at", "key_transition_signing_input");
  const currentKeyId = fetchBinary(input, "current_key_id", "key_transition_signing_input");
  const currentPublicKey = b64Field(input, "current_public_key", "key_transition_signing_input");
  const nextKeyId = fetchBinary(input, "next_key_id", "key_transition_signing_input");
  const nextPublicKey = b64Field(input, "next_public_key", "key_transition_signing_input");
  assert(currentPublicKey.length === 32 && nextPublicKey.length === 32, "key_transition_signing_input: key width");
  assert(!currentPublicKey.equals(nextPublicKey), "key_transition_signing_input: distinct keys");

  const header = { alg: "EdDSA", kid: currentKeyId, typ: "ba+key-transition" };
  const payload = {
    chain_id: chainId,
    effective_at: effectiveAt,
    from_key_fingerprint: jwkThumbprint(jwkFromPublicKey(currentPublicKey)),
    to_key_fingerprint: jwkThumbprint(jwkFromPublicKey(nextPublicKey)),
    to_key_id: nextKeyId,
    transition_id: transitionId,
    v: 1,
  };
  const protectedSegment = Buffer.from(canonical(header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(canonical(payload), "utf8").toString("base64url");
  return {
    protected_segment: protectedSegment,
    payload_segment: payloadSegment,
    message: `${protectedSegment}.${payloadSegment}`,
  };
}

// --- assemble_compact -------------------------------------------------------

function dispatchAssembleCompact(input) {
  const kind = fetchBinary(input, "kind", "assemble_compact");
  const protectedSegment = fetchBinary(input, "protected_segment", "assemble_compact");
  const payloadSegment = fetchBinary(input, "payload_segment", "assemble_compact");
  const signature = b64Field(input, "signature", "assemble_compact");
  // Kind must be a known signing-input kind (else the facade rejects).
  if (!["grant", "proof", "boundary_anchor", "key_transition"].includes(kind)) {
    fail("assemble_compact: unknown kind");
  }
  assert(signature.length === 64, "assemble_compact: signature width");
  const compact = `${protectedSegment}.${payloadSegment}.${signature.toString("base64url")}`;
  return { compact };
}

// --- decode grant/proof -----------------------------------------------------

function dispatchDecodeGrant(input) {
  const compact = fetchBinary(input, "compact", "decode_grant");
  const jws = parseCompactJws(compact, "decode_grant");
  const header = parseCanonicalJson(jws.protectedBytes, "decode_grant header");
  exactKeys(header, ["alg", "kid", "typ"], "decode_grant header");
  assert(header.alg === "EdDSA" && header.typ === "ba+cap", "decode_grant header values");
  return { key_id: header.kid };
}

function dispatchDecodeProof(input) {
  const compact = fetchBinary(input, "compact", "decode_proof");
  const jws = parseCompactJws(compact, "decode_proof");
  const header = parseCanonicalJson(jws.protectedBytes, "decode_proof header");
  assert(header.alg === "EdDSA" && header.typ === "dpop+jwt", "decode_proof header values");
  const payload = parseCanonicalJson(jws.payloadBytes, "decode_proof payload");
  return { proof_id: payload.jti };
}

// --- encode_consumption_entry ----------------------------------------------

function dispatchEncodeConsumptionEntry(input) {
  const chainId = fetchBinary(input, "chain_id", "encode_consumption_entry");
  const sequence = intField(input, "sequence", "encode_consumption_entry");
  const previousHash = b64Field(input, "previous_hash", "encode_consumption_entry");
  const commitment = b64Field(input, "commitment", "encode_consumption_entry");
  assert(sequence >= 1, "encode_consumption_entry: positive sequence");

  const row = {
    chain_id: chainId,
    commitment: commitment.toString("base64url"),
    previous: previousHash.toString("base64url"),
    sequence,
    v: 1,
  };
  const bytes = Buffer.from(canonical(row), "utf8");
  const hash = sha256(ROW_PREFIX, bytes).toString("base64url");
  return { bytes: bytes.toString("utf8"), hash };
}

// --- check_chain ------------------------------------------------------------

function dispatchCheckChain(input) {
  const rows = byteList(input, "rows", "check_chain").map((b) => b.toString("utf8"));
  const chainId = fetchBinary(input, "chain_id", "check_chain");
  const firstSequence = intField(input, "first_sequence", "check_chain");
  const lastSequence = intField(input, "last_sequence", "check_chain");
  const rowCount = intField(input, "row_count", "check_chain");
  const previousHash = b64Field(input, "previous_hash", "check_chain");
  const lastHash = b64Field(input, "last_hash", "check_chain");

  assert(rowCount === rows.length && rowCount > 0, "check_chain: row count");
  assert(lastSequence === firstSequence + rowCount - 1, "check_chain: range");
  assert(
    firstSequence !== 1 || previousHash.equals(DEFAULT_HASH),
    "check_chain: genesis predecessor",
  );
  let previous = previousHash;
  let sequence = firstSequence;
  for (const [i, rowText] of rows.entries()) {
    const rowBytes = Buffer.from(rowText, "utf8");
    const row = parseCanonicalJson(rowBytes, `check_chain row ${i}`);
    exactKeys(row, ["v", "chain_id", "sequence", "previous", "commitment"], `check_chain row ${i}`);
    assert(row.v === 1 && row.chain_id === chainId, `check_chain row ${i}: identity`);
    assert(row.sequence === sequence, `check_chain row ${i}: sequence`);
    equalBytes(strictB64(row.previous, 32), previous, `check_chain row ${i}: previous`);
    strictB64(row.commitment, 32);
    previous = sha256(ROW_PREFIX, rowBytes);
    sequence += 1;
  }
  equalBytes(previous, lastHash, "check_chain: head");
  return {};
}

// --- typed JSON algebra (mirrors runner.ex to_tagged / bap03 typedJsonMember) -
// The request digest and ba_req are computed over the typed-cast form, where each
// JSON value is wrapped in a [tag, value] pair that preserves the integer/float
// distinction. The canonical serialization of a tagged value is the JCS of its
// array form: ["integer",10], ["string","x"], ["object",{...}], etc.

function toTagged(value) {
  if (value === null) return ["null"];
  if (typeof value === "boolean") return ["boolean", value];
  if (typeof value === "string") return ["string", value];
  if (typeof value === "number") {
    return Number.isInteger(value) ? ["integer", value] : ["float", value];
  }
  if (Array.isArray(value)) return ["array", value.map((v, i) => taggedMember(value, i, v))];
  assert(value && typeof value === "object", "tagged JSON value");
  const obj = {};
  for (const [k, v] of Object.entries(value)) obj[k] = taggedMember(value, k, v);
  return ["object", obj];
}

function taggedMember(owner, key, value) {
  return toTagged(value);
}

// --- selector matching ------------------------------------------------------
// Mirrors the official Selector.match_all (lib/.../v1/selector.ex; protocol-v1 § Selector algebra):
// selectors apply CONJUNCTIVELY; `all` matches any root; `equals`/`one_of` require the path to
// exist, traversing OBJECTS ONLY (never index arrays) and comparing by SEMANTIC IDENTITY. Identity
// is the JCS of the tagged form — the same tagged projection ba_req uses — so it mirrors the
// official's tagged comparison exactly (int/float tags preserved, arrays positional, objects
// unordered). No selector grants business authorization; this is a bounded structural match only.
function traverseObjectPath(value, path) {
  let current = value;
  for (const segment of path) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) return undefined;
    if (!Object.prototype.hasOwnProperty.call(current, segment)) return undefined;
    current = current[segment];
  }
  return { found: current };
}

function taggedIdentity(value) {
  return canonical(toTagged(value));
}

function selectorMatches(selector, args) {
  if (selector && selector.kind === "all") return true;
  if (selector && selector.kind === "equals" && Array.isArray(selector.path)) {
    const hit = traverseObjectPath(args, selector.path);
    return hit !== undefined && taggedIdentity(hit.found) === taggedIdentity(selector.value);
  }
  if (selector && selector.kind === "one_of" && Array.isArray(selector.path) && Array.isArray(selector.values)) {
    const hit = traverseObjectPath(args, selector.path);
    if (hit === undefined) return false;
    const target = taggedIdentity(hit.found);
    return selector.values.some((v) => taggedIdentity(v) === target);
  }
  fail("check_envelope: selector shape");
}

// --- request_digest ---------------------------------------------------------

function requestDigest(operation, castArguments) {
  const jcs = canonical([operation, toTagged(castArguments)]);
  const preimage = Buffer.concat([REQUEST_PREFIX, Buffer.from(jcs, "utf8")]);
  return sha256(preimage).toString("base64url");
}

function dispatchRequestDigest(input) {
  const operation = fetchBinary(input, "operation", "request_digest");
  if (input.cast_arguments === undefined) fail("request_digest: cast_arguments");
  return { digest: requestDigest(operation, input.cast_arguments) };
}

// --- verify surfaces (Ed25519 via node:crypto — the import boundary) --------

function inWindow(time, key) {
  return (
    Number.isSafeInteger(time) &&
    time >= key.valid_from &&
    (key.valid_before === undefined || key.valid_before === null || time < key.valid_before)
  );
}

function buildHistoricalKey(keyMap, context) {
  const keyId = fetchBinary(keyMap, "key_id", context);
  const publicKey = b64Field(keyMap, "public_key", context);
  assert(publicKey.length === 32, `${context}: key width`);
  const validFrom = intField(keyMap, "valid_from", context);
  const validBefore = keyMap.valid_before;
  return {
    key_id: keyId,
    public_key: publicKey,
    fingerprint: fingerprint(publicKey).toString("base64url"),
    valid_from: validFrom,
    valid_before: validBefore === undefined ? null : validBefore,
  };
}

function dispatchVerifyGrant(input) {
  const compact = fetchBinary(input, "compact", "verify_grant");
  const keyId = fetchBinary(input, "key_id", "verify_grant");
  const publicKey = b64Field(input, "public_key", "verify_grant");
  assert(publicKey.length === 32, "verify_grant: key width");
  const issuer = fetchBinary(input, "issuer", "verify_grant");
  const audience = fetchBinary(input, "audience", "verify_grant");
  const evaluationTime = intField(input, "evaluation_time", "verify_grant");
  const clockSkew = intField(input, "clock_skew", "verify_grant");

  const jws = parseCompactJws(compact, "verify_grant");
  const header = parseCanonicalJson(jws.protectedBytes, "verify_grant header");
  exactKeys(header, ["alg", "kid", "typ"], "verify_grant header");
  assert(header.alg === "EdDSA" && header.typ === "ba+cap", "verify_grant header values");
  assert(header.kid === keyId, "verify_grant: kid");
  const payload = parseCanonicalJson(jws.payloadBytes, "verify_grant payload");
  assert(payload.v === 1, "verify_grant: version");
  assert(payload.iss === issuer, "verify_grant: issuer");
  assert(Array.isArray(payload.aud) && payload.aud.includes(audience), "verify_grant: audience");
  assert(payload.iat < payload.exp, "verify_grant: iat<exp");
  assert(payload.nbf < payload.exp, "verify_grant: nbf<exp");
  assert(payload.iat <= evaluationTime + clockSkew, "verify_grant: iat window");
  assert(payload.nbf <= evaluationTime + clockSkew, "verify_grant: nbf window");
  assert(payload.exp > evaluationTime - clockSkew, "verify_grant: exp window");

  const pub = nodePublicKey(publicKey, "verify_grant");
  assert(verifyEd25519(pub, jws.message, jws.signature), "verify_grant: Ed25519 signature");
  return {
    version: 1,
    issuer: payload.iss,
    grant_id: payload.jti,
    issuer_key_fingerprint: fingerprint(publicKey).toString("base64url"),
    holder_thumbprint: payload.cnf.jkt,
    matched_audience: audience,
    issued_at: payload.iat,
    not_before: payload.nbf,
    expires_at: payload.exp,
    authorization: "not_evaluated",
  };
}

function dispatchVerifyHistoricalAnchor(input) {
  const compact = fetchBinary(input, "compact", "verify_historical_anchor");
  const key = buildHistoricalKey(input.key ?? {}, "verify_historical_anchor key");
  const expected = input.expected ?? {};

  const jws = parseCompactJws(compact, "verify_historical_anchor");
  const header = parseCanonicalJson(jws.protectedBytes, "verify_historical_anchor header");
  assert(header.alg === "EdDSA" && header.typ === "ba+chain-anchor", "verify_historical_anchor header");
  assert(header.kid === key.key_id, "verify_historical_anchor: kid");
  const payload = parseCanonicalJson(jws.payloadBytes, "verify_historical_anchor payload");
  assert(payload.v === 1, "verify_historical_anchor: version");

  const anchorId = fetchBinary(expected, "anchor_id", "verify_historical_anchor expected");
  const anchoredAt = intField(expected, "anchored_at", "verify_historical_anchor expected");
  const chainId = fetchBinary(expected, "chain_id", "verify_historical_anchor expected");
  const sequence = intField(expected, "sequence", "verify_historical_anchor expected");
  const chainHash = b64Field(expected, "chain_hash", "verify_historical_anchor expected");
  const expectedKeyId = fetchBinary(expected, "key_id", "verify_historical_anchor expected");
  const keyFingerprint = b64Field(expected, "key_fingerprint", "verify_historical_anchor expected");

  assert(payload.anchor_id === anchorId, "verify_historical_anchor: anchor_id");
  assert(payload.anchored_at === anchoredAt, "verify_historical_anchor: anchored_at");
  assert(payload.chain_id === chainId, "verify_historical_anchor: chain_id");
  assert(payload.sequence === sequence, "verify_historical_anchor: sequence");
  equalBytes(strictB64(payload.chain_hash, 32), chainHash, "verify_historical_anchor: chain_hash");
  assert(payload.key_fingerprint === keyFingerprint.toString("base64url"), "verify_historical_anchor: key_fingerprint");
  assert(sequence !== 0 || chainHash.equals(DEFAULT_HASH), "verify_historical_anchor: genesis hash");
  assert(expectedKeyId === key.key_id, "verify_historical_anchor: expected key id");
  equalBytes(strictB64(key.fingerprint, 32), keyFingerprint, "verify_historical_anchor: fingerprint");
  assert(inWindow(anchoredAt, key), "verify_historical_anchor: window");

  const pub = nodePublicKey(key.public_key, "verify_historical_anchor");
  assert(verifyEd25519(pub, jws.message, jws.signature), "verify_historical_anchor: Ed25519 signature");
  return {};
}

function dispatchVerifyKeyTransition(input) {
  const compact = fetchBinary(input, "compact", "verify_key_transition");
  const currentKey = buildHistoricalKey(input.current_key ?? {}, "verify_key_transition current");
  const nextKey = buildHistoricalKey(input.next_key ?? {}, "verify_key_transition next");
  const expected = input.expected ?? {};

  const jws = parseCompactJws(compact, "verify_key_transition");
  const header = parseCanonicalJson(jws.protectedBytes, "verify_key_transition header");
  assert(header.alg === "EdDSA" && header.typ === "ba+key-transition", "verify_key_transition header");
  assert(header.kid === currentKey.key_id, "verify_key_transition: kid");
  const payload = parseCanonicalJson(jws.payloadBytes, "verify_key_transition payload");
  assert(payload.v === 1, "verify_key_transition: version");

  const transitionId = fetchBinary(expected, "transition_id", "verify_key_transition expected");
  const chainId = fetchBinary(expected, "chain_id", "verify_key_transition expected");
  const effectiveAt = intField(expected, "effective_at", "verify_key_transition expected");
  const currentKeyId = fetchBinary(expected, "current_key_id", "verify_key_transition expected");
  const currentKeyFingerprint = b64Field(expected, "current_key_fingerprint", "verify_key_transition expected");
  const nextKeyId = fetchBinary(expected, "next_key_id", "verify_key_transition expected");
  const nextKeyFingerprint = b64Field(expected, "next_key_fingerprint", "verify_key_transition expected");

  assert(currentKeyId === currentKey.key_id, "verify_key_transition: current key id");
  assert(nextKeyId === nextKey.key_id, "verify_key_transition: next key id");
  assert(!currentKey.public_key.equals(nextKey.public_key), "verify_key_transition: distinct keys");
  assert(payload.transition_id === transitionId, "verify_key_transition: transition_id");
  assert(payload.chain_id === chainId, "verify_key_transition: chain_id");
  assert(payload.effective_at === effectiveAt, "verify_key_transition: effective_at");
  assert(payload.from_key_fingerprint === currentKeyFingerprint.toString("base64url"), "verify_key_transition: from fp");
  assert(payload.to_key_fingerprint === nextKeyFingerprint.toString("base64url"), "verify_key_transition: to fp");
  assert(payload.to_key_id === nextKeyId, "verify_key_transition: to_key_id");
  equalBytes(strictB64(currentKey.fingerprint, 32), currentKeyFingerprint, "verify_key_transition: current fp");
  equalBytes(strictB64(nextKey.fingerprint, 32), nextKeyFingerprint, "verify_key_transition: next fp");
  assert(inWindow(effectiveAt, currentKey), "verify_key_transition: current window");
  assert(inWindow(effectiveAt, nextKey), "verify_key_transition: next window");

  const pub = nodePublicKey(currentKey.public_key, "verify_key_transition");
  assert(verifyEd25519(pub, jws.message, jws.signature), "verify_key_transition: Ed25519 signature");
  return {};
}

function dispatchCheckEnvelope(input) {
  const grantCompact = fetchBinary(input, "grant", "check_envelope");
  const proofCompact = fetchBinary(input, "proof", "check_envelope");
  const expected = input.expected ?? {};

  // Verify the grant (issuer signature).
  const trustedIssuer = expected.trusted_issuer ?? {};
  const grantKeyId = fetchBinary(trustedIssuer, "key_id", "check_envelope trusted issuer");
  const grantPublicKey = b64Field(trustedIssuer, "public_key", "check_envelope trusted issuer");
  assert(grantPublicKey.length === 32, "check_envelope: issuer key width");
  const grantJws = parseCompactJws(grantCompact, "check_envelope grant");
  const grantHeader = parseCanonicalJson(grantJws.protectedBytes, "check_envelope grant header");
  assert(grantHeader.alg === "EdDSA" && grantHeader.typ === "ba+cap", "check_envelope grant header");
  assert(grantHeader.kid === grantKeyId, "check_envelope: grant kid");
  const grantPayload = parseCanonicalJson(grantJws.payloadBytes, "check_envelope grant payload");
  const issuer = fetchBinary(expected, "issuer", "check_envelope");
  const audience = fetchBinary(expected, "audience", "check_envelope");
  const evaluationTime = intField(expected, "evaluation_time", "check_envelope");
  const clockSkew = intField(expected, "clock_skew", "check_envelope");
  const proofMaxAge = intField(expected, "proof_max_age", "check_envelope");
  assert(grantPayload.iss === issuer, "check_envelope: issuer");
  assert(Array.isArray(grantPayload.aud) && grantPayload.aud.includes(audience), "check_envelope: audience");
  assert(grantPayload.iat <= evaluationTime + clockSkew, "check_envelope: grant iat");
  assert(grantPayload.nbf <= evaluationTime + clockSkew, "check_envelope: grant nbf");
  assert(grantPayload.exp > evaluationTime - clockSkew, "check_envelope: grant exp");
  const grantPub = nodePublicKey(grantPublicKey, "check_envelope grant");
  assert(verifyEd25519(grantPub, grantJws.message, grantJws.signature), "check_envelope: grant signature");

  // Verify the proof (holder signature over the request).
  const proofJws = parseCompactJws(proofCompact, "check_envelope proof");
  const proofHeader = parseCanonicalJson(proofJws.protectedBytes, "check_envelope proof header");
  assert(proofHeader.alg === "EdDSA" && proofHeader.typ === "dpop+jwt", "check_envelope proof header");
  const proofPayload = parseCanonicalJson(proofJws.payloadBytes, "check_envelope proof payload");
  const holderJwk = exactPublicJwk(proofHeader.jwk, "check_envelope proof jwk");
  const holderPub = nodePublicKey(holderJwk.raw, "check_envelope proof");
  assert(verifyEd25519(holderPub, proofJws.message, proofJws.signature), "check_envelope: proof signature");

  // ath must equal sha256(grant compact).
  const ath = sha256(Buffer.from(grantCompact, "ascii")).toString("base64url");
  assert(proofPayload.ath === ath, "check_envelope: ath");
  // Method / URI / invocation / operation bindings: the proof's signed htm/htu/ba_inv/ba_op must
  // equal the expected request context (the profile binds every one; runtime.ex:485-491).
  const method = fetchBinary(expected, "method", "check_envelope");
  assert(proofPayload.htm === method, "check_envelope: method");
  const targetUri = fetchBinary(expected, "target_uri", "check_envelope");
  assert(proofPayload.htu === targetUri, "check_envelope: target_uri");
  const invocationId = fetchBinary(expected, "invocation_id", "check_envelope");
  assert(proofPayload.ba_inv === invocationId, "check_envelope: invocation_id");
  // ba_req must equal the request digest of (operation, cast_arguments).
  const operation = fetchBinary(expected, "operation", "check_envelope");
  assert(proofPayload.ba_op === operation, "check_envelope: operation");
  if (expected.cast_arguments === undefined) fail("check_envelope: cast_arguments");
  const baReq = requestDigest(operation, expected.cast_arguments);
  assert(proofPayload.ba_req === baReq, "check_envelope: ba_req");
  // Proof time window.
  assert(proofPayload.iat >= evaluationTime - proofMaxAge - clockSkew, "check_envelope: proof iat min");
  assert(proofPayload.iat <= evaluationTime + clockSkew, "check_envelope: proof iat max");
  // Nonce binding: absent expected.nonce => proof carries none; {required: n} => proof.nonce === n.
  const expNonce = expected.nonce;
  if (expNonce === undefined || expNonce === null) {
    assert(proofPayload.nonce === undefined, "check_envelope: nonce must be absent");
  } else if (expNonce && typeof expNonce === "object" && typeof expNonce.required === "string") {
    assert(proofPayload.nonce === expNonce.required, "check_envelope: nonce mismatch");
  } else {
    fail("check_envelope: expected nonce shape");
  }
  // Holder thumbprint must match the grant cnf.jkt.
  assert(grantPayload.cnf && grantPayload.cnf.jkt === jwkThumbprint(holderJwk), "check_envelope: holder thumbprint");
  // Selector binding: the grant operation named ba_op must exist UNIQUELY, and EVERY selector it
  // carries must match the server-derived cast_arguments (runtime.ex:497-498). Without this the
  // independent verifier would ignore grant selectors — the exact gap the check_envelope selector
  // fixtures exercise, so a corpus with a non-trivial selector would else silently disagree.
  const grantOperations = grantPayload.operations;
  assert(Array.isArray(grantOperations), "check_envelope: operations");
  const namedOps = grantOperations.filter((o) => o && o.name === operation);
  assert(namedOps.length === 1, "check_envelope: unique operation");
  const opSelectors = namedOps[0].selectors;
  assert(Array.isArray(opSelectors) && opSelectors.length >= 1, "check_envelope: selectors");
  assert(opSelectors.every((s) => selectorMatches(s, expected.cast_arguments)), "check_envelope: selector");
  return {};
}

// --- encode/verify anchored export -----------------------------------------

function buildExpectedAnchorRaw(expected, context) {
  return {
    anchor_id: fetchBinary(expected, "anchor_id", context),
    anchored_at: intField(expected, "anchored_at", context),
    chain_id: fetchBinary(expected, "chain_id", context),
    sequence: intField(expected, "sequence", context),
    chain_hash: b64Field(expected, "chain_hash", context),
    key_id: fetchBinary(expected, "key_id", context),
    key_fingerprint: b64Field(expected, "key_fingerprint", context),
  };
}

function dispatchEncodeAnchoredExport(input) {
  const rows = byteList(input, "rows", "encode_anchored_export").map((b) => b.toString("utf8"));
  const startAnchorCompact = fetchBinary(input, "start_anchor", "encode_anchored_export");
  const endAnchorCompact = fetchBinary(input, "end_anchor", "encode_anchored_export");
  const transitions = Array.isArray(input.transitions)
    ? input.transitions.map((t) => t)
    : [];
  const expected = input.expected ?? {};

  const chain = expected.chain ?? {};
  const header = {
    v: 1,
    chain_id: fetchBinary(chain, "chain_id", "encode_anchored_export chain"),
    first_sequence: intField(chain, "first_sequence", "encode_anchored_export chain"),
    last_sequence: intField(chain, "last_sequence", "encode_anchored_export chain"),
    row_count: intField(chain, "row_count", "encode_anchored_export chain"),
    transition_count: transitions.length,
    previous_hash: b64Field(chain, "previous_hash", "encode_anchored_export chain").toString("base64url"),
    last_hash: b64Field(chain, "last_hash", "encode_anchored_export chain").toString("base64url"),
  };
  const headerBytes = Buffer.from(canonical(header), "utf8");
  const archive = Buffer.concat([
    ARCHIVE_PREFIX,
    frame(headerBytes),
    frame(Buffer.from(startAnchorCompact, "ascii")),
    ...transitions.map((t) => frame(Buffer.from(t, "ascii"))),
    ...rows.map((r) => frame(Buffer.from(r, "utf8"))),
    frame(Buffer.from(endAnchorCompact, "ascii")),
  ]);
  return {
    digest: sha256(archive).toString("base64url"),
    byte_count: archive.length,
  };
}

function dispatchVerifyAnchoredExport(input) {
  const chunks = byteList(input, "chunks", "verify_anchored_export");
  const version = fetchBinary(input, "version", "verify_anchored_export");
  const keys = input.keys;
  if (!Array.isArray(keys)) fail("verify_anchored_export: keys");
  const expected = input.expected ?? {};

  const archive = Buffer.concat(chunks);
  assert(archive.length > ARCHIVE_PREFIX.length && archive.length <= 270820384, "verify_anchored_export: byte bound");
  const digest = b64Field(expected, "digest", "verify_anchored_export");
  equalBytes(sha256(archive), digest, "verify_anchored_export: digest");
  const objectVersion = fetchBinary(expected, "object_version", "verify_anchored_export");
  assert(version === objectVersion, "verify_anchored_export: object version");

  const parsed = parseArchive(archive);
  const chain = expected.chain ?? {};
  const headerChain = {
    v: 1,
    chain_id: fetchBinary(chain, "chain_id", "verify_anchored_export chain"),
    first_sequence: intField(chain, "first_sequence", "verify_anchored_export chain"),
    last_sequence: intField(chain, "last_sequence", "verify_anchored_export chain"),
    row_count: intField(chain, "row_count", "verify_anchored_export chain"),
    transition_count: (expected.transitions ?? []).length,
    previous_hash: b64Field(chain, "previous_hash", "verify_anchored_export chain").toString("base64url"),
    last_hash: b64Field(chain, "last_hash", "verify_anchored_export chain").toString("base64url"),
  };
  assert(canonical(parsed.header) === canonical(headerChain), "verify_anchored_export: header");

  // Verify start/end anchors and transitions against historical keys.
  const builtKeys = keys.map((k, i) => buildHistoricalKey(k, `verify_anchored_export key ${i}`));
  const startExpected = buildExpectedAnchorRaw(expected.start_anchor ?? {}, "verify_anchored_export start");
  const endExpected = buildExpectedAnchorRaw(expected.end_anchor ?? {}, "verify_anchored_export end");
  verifyAnchorCompact(parsed.start.toString("ascii"), builtKeys[0], startExpected, "verify_anchored_export start");
  verifyAnchorCompact(parsed.end.toString("ascii"), builtKeys[builtKeys.length - 1], endExpected, "verify_anchored_export end");
  const expectedTransitions = expected.transitions ?? [];
  assert(parsed.transitions.length === expectedTransitions.length, "verify_anchored_export: transition count");
  for (let i = 0; i < expectedTransitions.length; i += 1) {
    verifyTransitionCompact(
      parsed.transitions[i].toString("ascii"),
      builtKeys[i],
      builtKeys[i + 1],
      expectedTransitions[i],
      `verify_anchored_export transition ${i}`,
    );
  }
  return {};
}

function verifyAnchorCompact(compact, key, expected, context) {
  const jws = parseCompactJws(compact, context);
  const header = parseCanonicalJson(jws.protectedBytes, `${context} header`);
  assert(header.alg === "EdDSA" && header.typ === "ba+chain-anchor", `${context}: header`);
  assert(header.kid === key.key_id, `${context}: kid`);
  const payload = parseCanonicalJson(jws.payloadBytes, `${context} payload`);
  assert(payload.anchor_id === expected.anchor_id, `${context}: anchor_id`);
  assert(payload.anchored_at === expected.anchored_at, `${context}: anchored_at`);
  assert(payload.chain_id === expected.chain_id, `${context}: chain_id`);
  assert(payload.sequence === expected.sequence, `${context}: sequence`);
  equalBytes(strictB64(payload.chain_hash, 32), expected.chain_hash, `${context}: chain_hash`);
  assert(payload.key_fingerprint === expected.key_fingerprint.toString("base64url"), `${context}: key_fingerprint`);
  equalBytes(strictB64(key.fingerprint, 32), expected.key_fingerprint, `${context}: fingerprint`);
  assert(expected.key_id === key.key_id, `${context}: expected key id`);
  assert(inWindow(expected.anchored_at, key), `${context}: window`);
  assert(expected.sequence !== 0 || expected.chain_hash.equals(DEFAULT_HASH), `${context}: genesis hash`);
  const pub = nodePublicKey(key.public_key, context);
  assert(verifyEd25519(pub, jws.message, jws.signature), `${context}: Ed25519 signature`);
}

function verifyTransitionCompact(compact, currentKey, nextKey, expected, context) {
  const jws = parseCompactJws(compact, context);
  const header = parseCanonicalJson(jws.protectedBytes, `${context} header`);
  assert(header.alg === "EdDSA" && header.typ === "ba+key-transition", `${context}: header`);
  assert(header.kid === currentKey.key_id, `${context}: kid`);
  const payload = parseCanonicalJson(jws.payloadBytes, `${context} payload`);
  const transitionId = fetchBinary(expected, "transition_id", context);
  const chainId = fetchBinary(expected, "chain_id", context);
  const effectiveAt = intField(expected, "effective_at", context);
  const currentKeyId = fetchBinary(expected, "current_key_id", context);
  const currentKeyFingerprint = b64Field(expected, "current_key_fingerprint", context);
  const nextKeyId = fetchBinary(expected, "next_key_id", context);
  const nextKeyFingerprint = b64Field(expected, "next_key_fingerprint", context);
  assert(currentKeyId === currentKey.key_id, `${context}: current key id`);
  assert(nextKeyId === nextKey.key_id, `${context}: next key id`);
  assert(!currentKey.public_key.equals(nextKey.public_key), `${context}: distinct keys`);
  assert(payload.transition_id === transitionId, `${context}: transition_id`);
  assert(payload.chain_id === chainId, `${context}: chain_id`);
  assert(payload.effective_at === effectiveAt, `${context}: effective_at`);
  assert(payload.from_key_fingerprint === currentKeyFingerprint.toString("base64url"), `${context}: from fp`);
  assert(payload.to_key_fingerprint === nextKeyFingerprint.toString("base64url"), `${context}: to fp`);
  assert(payload.to_key_id === nextKeyId, `${context}: to_key_id`);
  equalBytes(strictB64(currentKey.fingerprint, 32), currentKeyFingerprint, `${context}: current fp`);
  equalBytes(strictB64(nextKey.fingerprint, 32), nextKeyFingerprint, `${context}: next fp`);
  assert(inWindow(effectiveAt, currentKey), `${context}: current window`);
  assert(inWindow(effectiveAt, nextKey), `${context}: next window`);
  const pub = nodePublicKey(currentKey.public_key, context);
  assert(verifyEd25519(pub, jws.message, jws.signature), `${context}: Ed25519 signature`);
}

// ===========================================================================
// Census
// ===========================================================================

function verifyCensus(index, manifest) {
  const declared = index.public_key_fingerprints;
  assert(
    canonical(declared) === canonical([...new Set(declared)].sort()),
    "index fingerprints not sorted/unique",
  );
  const observed = [...importedPublicKeyFingerprints].sort();

  // Published-mode census: the keys observed at the node:crypto import boundary must equal the
  // index's public_key_fingerprints exactly, both directions (spec: "census: import-boundary set
  // == index public_key_fingerprints always"). Hard two-way equality — no softness, because a
  // vacuous green (observed != declared, exit 0) is exactly the V4 hole this design exists to kill.
  assert(
    canonical(observed) === canonical(declared),
    `census: observed != index public_key_fingerprints observed=${observed.join(",")} declared=${declared.join(",")}`,
  );

  let manifestWired = false;

  if (manifest !== null) {
    assert(
      manifest.verifier_public_key_fingerprints &&
        typeof manifest.verifier_public_key_fingerprints === "object",
      "manifest verifier partitions",
    );
    const partition = manifest.verifier_public_key_fingerprints["corpus_independent.mjs"];
    if (partition !== undefined) {
      assert(
        canonical(partition) === canonical([...new Set(partition)].sort()),
        "manifest corpus partition not sorted",
      );
      assert(
        canonical(partition) === canonical(declared),
        "manifest corpus partition != index public_key_fingerprints",
      );
      const verifierSets = Object.values(manifest.verifier_public_key_fingerprints);
      const union = [...new Set(verifierSets.flat())].sort();
      const canonicalSet = [...manifest.canonical_public_key_fingerprints].sort();
      assert(canonical(canonicalSet) === canonical(union), "manifest three-partition union != canonical");
      manifestWired = true;
    }
  }
  return { observed: observed.length, declared: declared.length, partition: manifestWired };
}

// ===========================================================================
// main
// ===========================================================================

function parseArguments(argv) {
  const positional = [];
  let manifestPath = null;
  let scanPath = null;
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg === "--manifest") {
      if (i + 1 >= argv.length) throw new Error("usage");
      manifestPath = argv[i + 1];
      i += 2;
    } else if (arg === "--scan") {
      if (i + 1 >= argv.length) throw new Error("usage");
      scanPath = argv[i + 1];
      i += 2;
    } else if (arg.startsWith("--")) {
      throw new Error("usage");
    } else {
      positional.push(arg);
      i += 1;
    }
  }
  if (positional.length !== 1) throw new Error("usage");
  return { corpusDir: positional[0], manifestPath, scanPath };
}

function main() {
  const args = parseArguments(process.argv.slice(2));
  const corpusDir = resolve(args.corpusDir);

  const { index, cases, raws } = loadCorpus(corpusDir);

  // Independently recompute every case and check agreement.
  let agreed = 0;
  let disagreed = 0;
  const disagreements = [];
  for (const { caseObj } of cases) {
    let actual;
    try {
      actual = dispatch(caseObj.surface, caseObj.input ?? {}, raws);
    } catch (error) {
      // ONLY a genuine protocol rejection maps to INVALID. A runner bug (TypeError/ReferenceError/
      // an uncaught library throw) re-throws and aborts the run nonzero — it must never be laundered
      // into agreement on an invalid-expected case.
      if (!(error instanceof InvalidError)) throw error;
      actual = INVALID;
    }
    if (agree(caseObj.expected, actual)) {
      agreed += 1;
    } else {
      disagreed += 1;
      disagreements.push(caseObj.id);
    }
  }

  // Verification-import assertion (two-boundary census, design C2 / finding 4b): every key a VALID
  // verification-surface case declares must have been genuinely imported at node:crypto
  // createPublicKey during the run. This defeats a discovery-only census that stays green even if
  // the runner imports nothing. Producer-only keys (raw-thumbprint signing-input surfaces) never
  // reach createPublicKey and are correctly absent from the expected set — no false red.
  const VERIFICATION_SURFACES = new Set([
    "verify_grant",
    "verify_historical_anchor",
    "verify_key_transition",
    "check_envelope",
    "verify_anchored_export",
  ]);
  const expectedVerificationFingerprints = new Set();
  for (const { caseObj } of cases) {
    if (caseObj.class === "valid" && VERIFICATION_SURFACES.has(caseObj.surface)) {
      collectCaseKeys(caseObj.input ?? {}, expectedVerificationFingerprints);
    }
  }
  assert(
    expectedVerificationFingerprints.size > 0,
    "verification-import: no valid verification-surface keys discovered (corpus lost its verify cases)",
  );
  for (const fp of expectedVerificationFingerprints) {
    assert(
      verificationImportedFingerprints.has(fp),
      `verification-import: key ${fp} is declared by a valid verification case but was never imported ` +
        `at node:crypto createPublicKey (the runner did not actually verify it)`,
    );
  }

  // Census (Option D semantics: hard two-way equality once the index declares a
  // non-empty partition; reported visibly while empty).
  let manifest = null;
  if (args.manifestPath !== null) {
    manifest = readJsonFile(resolve(args.manifestPath), `manifest ${args.manifestPath}`);
  }
  const census = verifyCensus(index, manifest);

  const total = cases.length;
  process.stdout.write(
    `corpus_independent: agreed=${agreed} disagreed=${disagreed} total=${total} ` +
      `census_keys=${census.observed} declared=${census.declared} ` +
      `partition=${census.partition ? "wired" : "pending"}\n`,
  );

  if (disagreed > 0) {
    process.stderr.write(`corpus_independent: disagreements: ${disagreements.join(", ")}\n`);
  }
  if (disagreed > 0) {
    process.exitCode = 1;
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(`corpus_independent: error: ${error.message}\n`);
  process.exitCode = 1;
}
