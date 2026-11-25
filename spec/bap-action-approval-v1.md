# BAP Action Approval Profile 1

Document status: candidate normative contract for `bap-action-approval/1`.
This companion content profile defines the bytes of an approval record and how
a relying party verifies a content assertion over those bytes. The key words
**MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are interpreted as
described in BCP 14 only when they appear in all capitals.

## 1. Identity and purpose

An approval record describes one exact action on a set of resources, for one
subject and one immutable revision of the executing host's request. Subjects,
actions, resources and approver roles are deployment-defined identifiers. An
independently enrolled approver uses a signing backend to sign a content
assertion binding the exact record to the executing host as audience and a
validity window. Approval verification uses local inputs and
returns verification facts under explicitly supplied context and trust data
(`REQ-AA1-CORE-identity`).

The carrier is either [CA1](bap-content-assertion-v1.md) or
[ES256 Content Assertion 1](bap-content-assertion-es256-v1.md). This profile
defines neither a protected type nor new signed claims. The content assertion
facades treat content as opaque and keep their existing closed error contract.
The approval facade applies the record and diagnostic contract below
(`REQ-AA1-CORE-carrier`).

## 2. Record wire contract

The record is a JSON object with exactly these seven required members
(`REQ-AA1-RECORD-closed`).

| Member | Type and rule |
|---|---|
| `v` | JSON integer `1`. Booleans and float lexemes such as `1.0` and `1e0` are invalid. |
| `subject` | Nonempty scalar-valid string naming the subject of the action. |
| `action` | Nonempty scalar-valid string naming the exact action. |
| `request_id` | Nonempty scalar-valid string satisfying CA StringOrUri and its identifier bound. It names the request and is bound to assertion `sub`. |
| `approver_role` | Nonempty scalar-valid string naming the role used for this approval. |
| `resources` | Nonempty array of nonempty scalar-valid strings in strictly increasing unsigned UTF-8 byte order. |
| `revision_digest` | Canonical unpadded base64url of exactly 32 bytes, checked by decode and exact re-encode. The host supplies the independently derived digest of the immutable revision. |

Wire bytes MUST be the exact UTF-8 RFC 8785 JCS serialization of the closed
object, without a BOM, trailing newline, or any other additional bytes.
Detect duplicate object members, including equivalent escaped member names,
before constructing the object. Validate types, scalar validity, and the record
bounds, then require exact byte equality with the canonical re-encoding.
Alternate escapes, whitespace, member order, and all other byte differences
fail. JCS sorts object names by UTF-16 code units. The resource array order is
defined independently (`REQ-AA1-RECORD-canonical`).

A resource is identified by its decoded scalar UTF-8 bytes. Compare the byte
sequences lexicographically, each byte unsigned, with a proper prefix sorting
before the longer string. For example, U+E000 sorts before U+10000. Strict order
refuses duplicate strings as well as unsorted arrays. Scope equality requires
equal cardinality and exact element equality under this ordering. Text
throughout the record uses Unicode scalar values and exact UTF-8 equality.
Implementations MUST NOT normalize, case fold, trim, use a locale collation, or
replace invalid UTF-8 or unpaired surrogates. Composed and decomposed forms
remain distinct (`REQ-AA1-RECORD-set`, `REQ-AA1-RECORD-text`).

An authoring call produces JCS bytes and enforces the same schema and effective
limits as the record parser. By default it requires an already strictly ordered
set. An explicit authoring option MAY sort and deduplicate valid resource
strings before encoding. The producer applies raw-string and count limits to
the input before canonicalizing, and the encoded-size limit to the output.
A wire parser MUST reject unordered or duplicate entries without
repairing them (`REQ-AA1-RECORD-authoring`).

## 3. Bounds and profile identity

The record ceilings are independently tightenable. Fixed widths, schema rules,
and cryptographic formats remain fixed. Where limits overlap, the effective
ceiling is the smaller approval and selected CA ceiling, after caller
tightening. CA JSON structural, node and array bounds still apply to the
assertion. The record has its own closed grammar and the limits below
(`REQ-AA1-BOUND-minimum`).

| Item | Maximum or fixed width | Where enforced |
|---|---|---|
| Raw UTF-8 bytes of each `subject`, `action`, `approver_role` and resource | 1,024 each | Authoring input, record parser, matching expected text, and snapshot role names. |
| Raw UTF-8 bytes of `request_id` | 1,024, intersected with CA `identifier_bytes` (512 at its default ceiling) | Authoring input, record parser, expected request ID and signed `sub`. |
| Resource items | 4,096 | Authoring input, record parser and expected resource set. |
| Encoded record | 65,536 bytes, intersected with CA `content_bytes` | Source read, authoring output and record parser. For expected scope, enforce count and raw byte ceilings. The encoded-record ceiling applies to the complete record. |
| `revision_digest` | 32 decoded bytes, 43 unpadded base64url characters on the wire | Authoring input, record parser and expected revision. |
| Assertion compact | Selected CA `anchor_bytes` and all applicable compact and segment bounds | Assertion source read, producer, assembler and verifier. Count original compact bytes. |
| CA identifiers and key IDs | Selected CA `identifier_bytes` or `kid_bytes`, respectively | Assertion producer/parser, matching expected identifiers and snapshot entries. |
| Time, generation and policy integers | Selected CA `integer_magnitude` (at most 9,007,199,254,740,991) | As applicable to assertion, key windows, snapshot time and context. |

Reject oversize sources before unbounded buffer growth. Bound the compact and
record reads independently, then enforce raw decoded string lengths, token
counts and encoded sizes separately. A small decoded string can require more
bytes after JCS escaping. Scan within the effective byte, string and count
ceilings before allocating storage for an over-limit input. A host loading a
snapshot from a file MUST apply trusted source-size and entry-count ceilings
before allocation and enforce the applicable per-field ceilings above before
admission. The snapshot file format and its aggregate ceilings are host policy
(`REQ-AA1-BOUND-ordering`).

The signed `profile` MUST equal `bap-action-approval/1`. The signed
`profile_digest` MUST bind the exact frozen
[record descriptor](profiles/bap-action-approval-v1.descriptor.json).
The descriptor states the canonical encoding, closed record shape, text and
set rules, and bounds and their composition with CA. Use its published UTF-8
JCS bytes verbatim, with no trailing bytes. Compute:

```text
profile_digest = SHA-256(UTF8("bap-action-approval/1") || 0x00 || descriptor_bytes)
```

The preimage contains exactly one domain separator byte between the identity
and descriptor. Encode the raw 32-byte digest in the assertion according to
the selected CA rules. The separately signed `content_digest` is SHA-256 over
`UTF8("BAP1-CONTENT") || 0x00 || record_bytes` for either suite. The descriptor
pin identifies the fixed record contract independently of runtime tightening.
It MUST remain byte-for-byte frozen once certified. Any change to accepted
profile semantics requires a new identifier and digest
(`REQ-AA1-PROFILE-digest`).

| Known answer | Hex value at candidate freeze |
|---|---|
| Profile digest preimage | `TBD-by-reference-implementation` |
| Profile digest | `TBD-by-reference-implementation` |

Publish both values from the reference implementation and independently
reproduce them before certification (`REQ-AA1-PROFILE-known-answer`).

## 4. Approval verification

### 4.1 Pure interface and suite selection

The pure interface is
`verify_approval(suite, record_bytes, assertion_compact, context)`. It returns
`VerifiedApprovalFacts` or a value-free `Diagnostic` code. Implementations MUST
expose two named, statically bound entry points, one for `EDDSA` (CA1) and one
for `ES256` (ES256 Content Assertion 1). The relying party selects one suite from
independent operation configuration before reading any presented bytes.
A deployment using both suites configures two separate contexts. The selected
suite determines the only permitted `alg`, `typ`, parser and key snapshot.
A foreign-suite compact that passes framing and header shape MUST fail suite
admission before payload parsing or key lookup. There is no retry, fallback or
byte-driven dispatch (`REQ-AA1-VERIFY-suite`).

The pure facade MUST use explicit inputs only. It MUST NOT perform I/O, read a
clock, call host predicates, discover keys, mutate state, or make an execution
decision. The record, compact and context used throughout a call MUST be
immutable, owned, or safely borrowed for the duration
(`REQ-AA1-VERIFY-pure`).

### 4.2 Context and snapshot preflight

Validate the suite, independently configured trust domain, expected values,
policy, and effective bounds before processing presented bytes. The expected
audience, request ID, revision digest, subject, action, exact resource set and
nonempty expected approver role set MUST come from the operation the host will
execute. The decision to require approval and the eligible approver roles come
from the host's own operation policy. The expected audience identifies the
executing host and obeys CA identifier rules, as does the request ID. The expected
revision is a raw 32-byte value. Match resource and role strings using the
record's exact text semantics. Expected resources form a set under section 2
and use its count and per-string ceilings. The trust-domain identity is an
independently supplied nonempty scalar string within CA `identifier_bytes`
(`REQ-AA1-CONTEXT-expected`).

The policy contains `now`, `max_staleness`, `max_lifetime` and, optionally,
`max_active`. The host supplies trusted current time. `now` is a signed CA
NumericDate. Ceilings are nonnegative and inclusive. All times and ceilings are
exact bounded integers. Reject booleans, floats and out-of-range values.
Evaluate differences exactly, including opposite-sign NumericDate endpoints
whose difference exceeds the input magnitude ceiling. Invalid or missing
expected values, policy or bounds return `invalid_context`
(`REQ-AA1-CONTEXT-time`).

The snapshot is an immutable, caller-admitted view for one independently
configured trust domain and one suite, with provenance established independently
of the presented bytes. Validate domain, suite, provenance and `as_of` metadata
as part of preflight. `as_of` is a signed CA NumericDate. A missing, unavailable,
malformed or wrong-domain/suite snapshot, including malformed metadata, returns
`trust_unavailable`. A valid snapshot is usable only when
`0 <= now - as_of <= max_staleness`. A future timestamp or age above the cap
returns `stale_trust`. The host is responsible for supplying current trust
state and handling rollback when it requires monotonic continuity
(`REQ-AA1-CONTEXT-snapshot`).

Each admitted entry with a unique CA `kid` contains one enrolled issuer,
a public key and its fingerprint, its historical validity window, and its
current approver role set. The issuer obeys CA StringOrUri and identifier bounds.
Admit strict torsion-free Ed25519 keys per
[BAP v1 § 14.1](bap-v1.md#strict-ed25519), or P-256 keys under
[BAP v3 § 3.1](bap-v3.md#31-keys-and-the-proof-jwk), before installing the
snapshot or making fingerprint-based deny comparisons. Compute or validate the
fingerprint using the selected CA profile. Refuse duplicate key IDs at
admission. `valid_from` is a finite signed NumericDate. `valid_before` is a
finite signed NumericDate greater than `valid_from`, or explicitly unbounded.
The snapshot provides current role eligibility at the supplied verification
time. Signing-window containment uses the historical key window
(`REQ-AA1-CONTEXT-entries`).

### 4.3 Ordered outcome contract

The first failing check in this order MUST determine the returned code.
Internal stages return typed outcomes. Exception text has no role in selecting
an outcome. Once header shape passes, a well-typed unequal algorithm or type
belongs to suite admission (`REQ-AA1-VERIFY-precedence`).

| Stage | Code or result | Check |
|---|---|---|
| 1 | `invalid_context`, then `trust_unavailable`, then `stale_trust` | Check explicit expected values and policy, then snapshot availability, admission and metadata, then snapshot freshness, as specified in § 4.2. |
| 2 | `malformed` | Enforce bounded three-segment compact framing, canonical base64url segment encodings, a canonical closed protected header with exactly the correctly typed `alg`, `typ` and valid `kid`, and a signature width of exactly 64 bytes. This checks payload segment encoding without parsing the payload. |
| 3 | `unsupported_algorithm` | Require exact `alg` and `typ` values for the preselected suite. |
| 4 | `malformed` | Enforce the selected CA's payload form, limits and structural claims rules. Parse the original record under sections 2–3, including bounds, exact canonical bytes and schema. |
| 5 | `unknown_key` | Look up the protected `kid` solely in the already-admitted snapshot for the selected suite. |
| 6 | `bad_signature` | Verify the original JWS signing input against the admitted key with strict Ed25519 or strict P-256 ES256, including low-S. Invalid points, scalars or equations, and backend verification failures, fail here. |
| 7 | `key_window` | Require `iat >= valid_from`, `nbf >= valid_from`, and `exp <= valid_before` for a finite `valid_before`. Equality at the finite endpoint passes. |
| 8 | `record_mismatch` | Require exact `content_digest` of the supplied record bytes, `profile` and `profile_digest` under section 3. |
| 9 | `issuer_mismatch`, then `audience_mismatch` | Require `iss` equal to the enrolled issuer and then `aud` equal to the independently expected audience. |
| 10 | `request_mismatch` | Require `record.request_id == expected.request_id == assertion.sub` and `record.revision_digest == expected.revision_digest`. |
| 11 | `subject_mismatch`, then `scope_mismatch` | Require exact expected subject, then exact action, then exact resource-set equality. |
| 12 | `not_yet_valid`, then `expired` | Require `nbf <= now`, then `now < exp`. Use no implicit skew. |
| 13 | `lifetime_too_long`, then `active_too_long` | Require `exp - iat <= max_lifetime`, then `exp - nbf <= max_active` if configured. |
| 14 | `role_not_permitted` | Require the record's approver role in the expected approver role set and in the key entry's current approver role set. |
| 15 | `VerifiedApprovalFacts` | Return facts only after all checks pass. |

Stages 7–14 MUST use authenticated claims. Stage 4 checks structure only.
Use vetted constant-time comparison primitives for fixed-width digest and
fingerprint equality checks (`REQ-AA1-VERIFY-authenticated`).

Each SDK MUST share one staged content assertion implementation between its
standalone CA facades and the approval facade. Share bounded parsing, exact
signature primitives, reusable claim checks and facts construction. Parse
each artifact once. The standalone CA facades retain their verification order
and collapse failures to their existing closed `invalid`. The approval facade
selects the order in the table and reports its own versioned codes. Keep
artifacts, assemblers and facts provenance distinct by suite
(`REQ-AA1-VERIFY-shared-stages`).

### 4.4 Facts and rendering

`VerifiedApprovalFacts` carries exactly the selected `suite`, verified
`trust_domain` from the caller's context, the decoded `record` from the
canonical bytes, the selected suite's verified `assertion` facts, and
`trust: not_evaluated`. The assertion
facts carry the verified issuer, artifact ID, key ID and fingerprint, validity
window, and exact compact digest per the selected CA spec. The record's
revision digest is raw 32-byte data in facts. No raw signature, compact, public
key or snapshot entry is returned in the facts. Facts prove checks against
supplied context. They carry no operational decision or execution credential
(`REQ-AA1-VERIFY-facts`).

Render facts and result wrappers using
[diagnostic rendering](diagnostic-rendering.md). Default inspection, string
conversion and log serialization MUST redact every value, including nested
strings and digests. Only static result/type markers and an authorized host-local
diagnostic code are eligible for default rendering
(`REQ-AA1-VERIFY-redaction`).

## 5. Host helper and disclosure

The host helper takes `record_bytes`, `assertion_compact`, `trusted_keys`,
`now`, `max_validity`, `is_replayed` and `is_revoked`, with explicit suite,
expected context and remaining policy inputs. `max_validity` maps to
`max_lifetime`. It invokes the pure facade first, then uses the same immutable
snapshot and the entry admitted for the verified assertion. The helper
returns an `ApprovalResult` with either `Approved(facts)` or a closed failure
code. This is a read-only convenience over the pure result
(`REQ-AA1-HOST-helper`).

Both predicates are synchronous, local and read-only. After pure success,
call `is_revoked(entry, fingerprint)` exactly once. Exact boolean true
terminates with `revoked_key`. Exact boolean false proceeds to one call to
`is_replayed(trust_domain, iss, jti)`. Exact boolean true returns `replayed`
and exact boolean false returns `Approved(facts)`. No predicate runs on any
pure failure. An unavailable store, non-boolean result, exception, panic or
cancellation returns `predicate_failed` immediately. Discard the original
cause outside its handler so it cannot appear in chains, tracebacks or logs.
The helper MUST NOT raise for verification or predicate failures and MUST NOT
retry or fall back to an allowing predicate (`REQ-AA1-HOST-predicates`).

Detailed codes are host-local diagnostics for operators and local event logs.
Every presenter-facing verification failure MUST collapse to the same
value-free `invalid` result, including in remote alerts and presenter-accessible
logs. Diagnostic payloads, facts, nested record fields, and original predicate or
provider causes MUST NOT be serialized into those surfaces. Local event logging
may retain only the static result marker and code. Apply the same boundary to
pre-authentication results such as `unknown_key`
(`REQ-AA1-HOST-disclosure`).

## 6. Execution and trust boundaries

The host MUST bind execution to the exact independently prepared effect. In
the effect's transaction, conditionally insert `(trust_domain, iss, jti)` and
the host-scoped `(request_id, revision_digest)` under uniqueness constraints.
Refuse a second use. A read-only replay check cannot make the conditional
inserts. When the effect cannot join the transaction, the host MUST use durable
intent and destination idempotency. For an indeterminate outcome, look up the
effect at the destination, including after a restart. A retry MAY resubmit
the stored artifact. The host refuses or re-executes according to its own
rule. It MUST NOT return an earlier result
(`REQ-AA1-EXEC-claim`).

In the transaction for the effect or its durable intent, the host MUST read the
revision its own request record holds as current. Execute only when that revision digest equals the exact
`revision_digest` in the approval. Refuse every other revision
(`REQ-AA1-EXEC-current-revision`).

The artifact binds an enrolled key to a record, audience and window. A claim
of human assent additionally requires independently established approver
identity, custody isolated from the requesting application, and an enrolled
policy requiring human confirmation of these exact bytes on each use.
Unattended signing can establish human assent only with independently enrolled,
transaction-bound human authorization. The host authenticates the executor.
An operation requiring proof of executor key possession uses a capability grant
with an exact record-digest selector and a holder proof
(`REQ-AA1-SECURITY-assent`).

## 7. Conformance and release

The candidate corpus root is `priv/conformance/content-profiles/action-approval/v1`.
Use one frozen `index.json` covering the following case files. Index SHA-256 (hex) at freeze
is `TBD-by-reference-implementation`. Consumers MUST pin the index and verify
its indexed file hashes (`REQ-AA1-CONFORMANCE-pin`).

| File | Inputs and expected results |
|---|---|
| `record-cases.json` | Exact wire bytes or typed authoring input, effective bounds, canonical output bytes or rejection, and independent descriptor/content known answers. Cover each schema field, duplicates and escapes, Unicode scalar and UTF-8 ordering edges, normalization distinctions, explicit authoring deduplication, and simultaneous raw-string/count/encoded-byte and CA tightening edges. |
| `approval-cases.json` | Public compact and record bytes, selected suite, explicit expected context, bounds, time and snapshot, and exact facts or one named pure diagnostic. Cover every pure code, each time and containment edge, both suites, and cross-profile and foreign-suite rejection. |
| `multi-fault-cases.json` | The same public inputs with independent faults and the winning pure diagnostic. Cover preflight and snapshot freshness over malformed input, structure over suite, suite over payload and key lookup, bad signature over signed times/key windows, and ordering among authenticated failures. |

Independent implementations MUST agree on canonical bytes, digest values and
every verdict. Keep all old known-answer verdicts and demonstrate red-capable
mutations for every material predicate and precedence boundary. A foreign-suite
case with a valid independently enrolled signer in each suite MUST show zero
calls into the other verifier. Exercise host predicate outcomes, exact call
counts, short-circuiting and zero calls on pure failures in host tests. Check
presenter-visible and local log serialization and default rendering with
distinct canaries and base64url, hex and JSON-escaped forms, including nested
record fields, tracebacks, chained contexts, and provider causes
(`REQ-AA1-CONFORMANCE-cases`).

All maintained SDKs MUST certify against the exact immutable candidate before
the first bearing package release. Consumer qualification MUST include a tested
offline verifier README example titled “Verifying a grant before issuing it”,
linked from the signer README. It exercises independent context and trust
inputs, exact effect and set matching, conditional inserts and refusal of a
second use, exact current-revision comparison, and destination lookup after
restart for an indeterminate effect. It explains when to use a capability
grant and holder proof
(`REQ-AA1-CONFORMANCE-release`).
