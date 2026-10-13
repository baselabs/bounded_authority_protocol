// Pure BigInt Ed25519 reference arithmetic for the strict-Ed25519 corpus generator.
//
// Authoring tooling only (not a conformance runner, not part of the published package). It is the
// SOURCE OF EXPECTED VERDICTS for priv/conformance/strict-ed25519/v1: every verdict is computed
// here from first principles (RFC 8032 section 5.1 field and group arithmetic), with
//
//   - no Ed25519 backend (node:crypto is never called from this module),
//   - no small-order blocklist (small order is the arithmetic test [8]P == O),
//   - no canonical-encoding byte table (canonical is "the strict RFC 8032 section 5.1.3 decode
//     succeeds": y < p, and no sign bit when x = 0).
//
// SHA-512 (the challenge hash) comes from node:crypto createHash; it is a hash, not a signature
// backend. The generator cross-checks every verdict produced here against node:crypto verify behind
// the byte-level S1 gate and fails generation on any disagreement.
//
// Points use extended twisted Edwards coordinates (X:Y:Z:T), a = -1, with the complete
// add-2008-hwcd-3 addition law (complete on edwards25519 because d is a non-square), so the
// identity and every torsion point are handled by the same formula.

import { createHash } from "node:crypto";

export const P = 2n ** 255n - 19n;
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const mod = (x) => {
  const r = x % P;
  return r < 0n ? r + P : r;
};

export function powmod(base, exponent, modulus = P) {
  let result = 1n;
  let b = base % modulus;
  if (b < 0n) b += modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

const inv = (x) => powmod(x, P - 2n);
export const D = mod(-121665n * inv(121666n));
const SQRT_M1 = powmod(2n, (P - 1n) / 4n);
const D2 = mod(2n * D);

export const IDENTITY = Object.freeze([0n, 1n, 1n, 0n]);

export function add(p1, p2) {
  const [x1, y1, z1, t1] = p1;
  const [x2, y2, z2, t2] = p2;
  const a = mod((y1 - x1) * (y2 - x2));
  const b = mod((y1 + x1) * (y2 + x2));
  const c = mod(t1 * D2 * t2);
  const d = mod(2n * z1 * z2);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

export function negate([x, y, z, t]) {
  return [mod(-x), y, z, mod(-t)];
}

export function multiply(scalar, point) {
  if (scalar < 0n) throw new Error("negative scalar");
  let result = IDENTITY;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = add(result, addend);
    addend = add(addend, addend);
    k >>= 1n;
  }
  return result;
}

export function pointEquals([x1, y1, z1], [x2, y2, z2]) {
  return mod(x1 * z2 - x2 * z1) === 0n && mod(y1 * z2 - y2 * z1) === 0n;
}

export function isIdentity(point) {
  return pointEquals(point, IDENTITY);
}

export function encodePoint([x, y, z]) {
  const zi = inv(z);
  const ax = mod(x * zi);
  const ay = mod(y * zi);
  const value = ay | ((ax & 1n) << 255n);
  return bigToLe(value, 32);
}

export function bigToLe(value, width) {
  const out = Buffer.alloc(width);
  let v = value;
  for (let i = 0; i < width; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error("value does not fit width");
  return out;
}

export function leToBig(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

// RFC 8032 section 5.1.3 steps 2-4 square root; returns x or null (no square root: off curve).
function recoverX(y, sign) {
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  const x2 = mod(u * inv(v));
  if (x2 === 0n) return { x: 0n, zeroWithSign: sign === 1n };
  let x = powmod(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null;
  if ((x & 1n) !== sign) x = P - x;
  return { x, zeroWithSign: false };
}

// Classifies a 32-byte encoding. Returns
//   { kind: "point", point }          strict RFC 8032 decode succeeds (canonical, on curve)
//   { kind: "noncanonical", point }   y >= p, or x = 0 with the sign bit; point = the lenient
//                                      (reduce-y, drop-sign) decoding, or null if that is off curve
//   { kind: "offcurve" }               canonical y with no square root
export function classifyEncoding(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) throw new Error("32-byte encoding required");
  const v = leToBig(bytes);
  const sign = v >> 255n;
  let y = v & ((1n << 255n) - 1n);
  let noncanonical = false;
  if (y >= P) {
    noncanonical = true;
    y -= P;
  }
  const recovered = recoverX(y, sign);
  if (recovered === null) return noncanonical ? { kind: "noncanonical", point: null } : { kind: "offcurve" };
  if (recovered.zeroWithSign) noncanonical = true;
  const point = [recovered.x, y, 1n, mod(recovered.x * y)];
  return noncanonical ? { kind: "noncanonical", point } : { kind: "point", point };
}

export function strictDecode(bytes) {
  const c = classifyEncoding(bytes);
  return c.kind === "point" ? c.point : null;
}

// Lenient (ref10-style) decode: reduce y mod p, accept x = 0 with the sign bit. Used only to
// CONSTRUCT forgeries that an ungated cofactorless backend accepts; never for a verdict.
export function lenientDecode(bytes) {
  const c = classifyEncoding(bytes);
  if (c.kind === "offcurve") return null;
  return c.point;
}

const BY = mod(4n * inv(5n));
export const BASE = strictDecode(bigToLe(BY, 32));
if (BASE === null) throw new Error("base point decode failed");

export function isSmallOrder(point) {
  return isIdentity(multiply(8n, point));
}

export function isTorsionFree(point) {
  return isIdentity(multiply(L, point));
}

export function sha512(...parts) {
  const h = createHash("sha512");
  for (const part of parts) h.update(part);
  return h.digest();
}

export function challenge(rBytes, aBytes, message) {
  return leToBig(sha512(rBytes, aBytes, message)) % L;
}

// ---- verdicts (the corpus's expected values) ----------------------------------------------

// S1 verify_strict, pure arithmetic. Returns { valid, reason } where reason is the FIRST failing
// clause in a fixed order (used for rule attribution of multi-violation vectors):
//   width, a-noncanonical, a-small-order, r-noncanonical, r-small-order, s-range,
//   a-off-curve (the rule leaves curve membership of A to the backend), equation.
export function verifyStrict(publicKey, signature, message) {
  if (publicKey.length !== 32 || signature.length !== 64) return { valid: false, reason: "width" };
  const rBytes = signature.subarray(0, 32);
  const s = leToBig(signature.subarray(32));
  const a = classifyEncoding(publicKey);
  if (a.kind === "noncanonical") return { valid: false, reason: "a-noncanonical" };
  if (a.kind === "point" && isSmallOrder(a.point)) return { valid: false, reason: "a-small-order" };
  const r = classifyEncoding(rBytes);
  if (r.kind === "noncanonical") return { valid: false, reason: "r-noncanonical" };
  if (r.kind === "point" && isSmallOrder(r.point)) return { valid: false, reason: "r-small-order" };
  if (s >= L) return { valid: false, reason: "s-range" };
  if (a.kind === "offcurve") return { valid: false, reason: "a-off-curve" };
  const k = challenge(rBytes, publicKey, message);
  const lhs = add(multiply(s, BASE), negate(multiply(k, a.point)));
  if (!encodePoint(lhs).equals(rBytes)) return { valid: false, reason: "equation" };
  return { valid: true, reason: null };
}

// What an UNGATED lenient cofactorless backend computes (ref10/OpenSSL shape: lenient decode of
// A, S < L, R compared byte for byte). Construction aid: a forged vector must satisfy this, which
// proves the forgery is real (accepted without the strict rule), not trivially invalid.
export function verifyUngatedCofactorless(publicKey, signature, message) {
  const a = lenientDecode(publicKey);
  if (a === null) return false;
  const rBytes = signature.subarray(0, 32);
  const s = leToBig(signature.subarray(32));
  if (s >= L) return false;
  const k = challenge(rBytes, publicKey, message);
  const lhs = add(multiply(s, BASE), negate(multiply(k, a)));
  return encodePoint(lhs).equals(rBytes);
}

// acceptable_public_key?: 32 bytes, canonical, on the curve, not small order.
export function acceptablePublicKey(publicKey) {
  if (publicKey.length !== 32) return { valid: false, reason: "width" };
  const a = classifyEncoding(publicKey);
  if (a.kind === "noncanonical") return { valid: false, reason: "a-noncanonical" };
  if (a.kind === "offcurve") return { valid: false, reason: "a-off-curve" };
  if (isSmallOrder(a.point)) return { valid: false, reason: "a-small-order" };
  return { valid: true, reason: null };
}

// torsion_free?: acceptable_public_key? and [L]A == O.
export function torsionFree(publicKey) {
  const acceptable = acceptablePublicKey(publicKey);
  if (!acceptable.valid) return acceptable;
  if (!isTorsionFree(strictDecode(publicKey))) return { valid: false, reason: "a-mixed-order" };
  return { valid: true, reason: null };
}

// ---- signing (honest and key-holder constructions) ----------------------------------------

export function expandSeed(seed) {
  const h = sha512(seed);
  let a = leToBig(h.subarray(0, 32));
  a &= (1n << 254n) - 8n;
  a |= 1n << 254n;
  return { scalar: a, prefix: h.subarray(32) };
}

export function publicKeyFromSeed(seed) {
  return encodePoint(multiply(expandSeed(seed).scalar, BASE));
}

// RFC 8032 section 5.1.6, deterministic.
export function signHonest(seed, message, publicKey = publicKeyFromSeed(seed)) {
  const { scalar, prefix } = expandSeed(seed);
  const r = leToBig(sha512(prefix, message)) % L;
  const rBytes = encodePoint(multiply(r, BASE));
  const k = challenge(rBytes, publicKey, message);
  const s = (r + k * scalar) % L;
  return Buffer.concat([rBytes, bigToLe(s, 32)]);
}

// The 8 points of E[8] as multiples of one order-8 point, derived by arithmetic: T[i] = [i]T1.
export function torsionPoints() {
  for (let y = 2n; ; y += 1n) {
    const candidate = strictDecode(bigToLe(y, 32));
    if (candidate === null) continue;
    const t = multiply(L, candidate);
    if (!isIdentity(multiply(4n, t))) {
      const points = [];
      let acc = IDENTITY;
      for (let i = 0; i < 8; i += 1) {
        points.push(acc);
        acc = add(acc, t);
      }
      return points;
    }
  }
}

export function pointOrder(point) {
  for (const order of [1n, 2n, 4n, 8n]) if (isIdentity(multiply(order, point))) return Number(order);
  return null;
}
