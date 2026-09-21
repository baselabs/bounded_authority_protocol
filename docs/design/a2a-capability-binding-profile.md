# A2A capability-binding profile — design specification

Status: accepted — owner approval 2026-09-20, following the project's design method: an options
analysis over the binding-layer fork, then independent adversarial review of both the analysis
and this specification (two review rounds each; every finding adjudicated against first-hand
sources and repaired). This document changes no wire format, public API, verifier behavior, or
package dependency. It is the A2A counterpart of the [AP2 interop profile](ap2-interop-profile.md)'s
§6 open question, decided through the same method; it composes with — does not replace — A2A's
authentication surfaces.

Evidence classes at load-bearing claims:

- **OBSERVED** — verified first-hand against the A2A specification and proto at pinned commit
  `afda8316c64951a2ecb2a0d3d10867405d2b4095`
  ([a2aproject/A2A](https://github.com/a2aproject/A2A)), or against this repository at
  `fb83133` (the v1/v2 specs, registries, ADRs, the BAP-08 drafts, the AP2 interop profile,
  the successor-major charter), or against the gRPC over HTTP/2 protocol specification at its
  pinned commit (§1).
- **DERIVED** — restated from a program record; not re-verified for this document.
- **INFERRED** — this document's own design decisions, verifiable against no source.

## 0. Scope and framing

This profile specifies how a Bounded Authority Protocol grant + holder proof binds an A2A
request: where the artifacts ride on each standard A2A binding, which request surface the proof
cryptographically binds, how an A2A deployment discovers and negotiates the binding, and what
the binding deliberately does not cover. The framing is the owner's settled sentence carried
into A2A terms: BAP composes with A2A's authentication/authorization surfaces and never
replaces them. A capability narrows what the card's declared security schemes permit; it never
widens anything.

The binding decision this document implements is **composition** (§3): discovery and
negotiation at the A2A layer via A2A's own extension mechanism; cryptographic binding and
carriage at the transport layer per the RFC 9449-shaped structure the v1 profile already
incorporates. The grant and proof bytes are the unchanged published v1/v2 artifacts.

Explicit non-claims (the [AP2 interop profile](ap2-interop-profile.md) §0 discipline,
extended):

- no claim that an A2A-conforming agent can consume a BAP grant + proof (unverified);
- no claim that A2A's authentication validates either artifact;
- no claim that BAP verification yields an authorization decision, receipt, or any runtime
  guarantee — verification is not authority (repository critical rule 1); replay reservation,
  revocation state, and the server's authorization decision remain the A2A server's own
  (A2A §7.5, §13.1 say the same in A2A's vocabulary: authorization logic is the agent's own);
- no interop claim resting on self-round-trips (repository workflow rule);
- no submission to, or upstream contribution toward, any A2A or standards body (owner-gated;
  `docs/standards/submissions.md` reads "Nothing has been submitted").

The binding covers a defined surface. **In scope:** the three standard A2A bindings over
HTTPS — JSON-RPC (HTTP/S), HTTP+JSON/REST, gRPC (HTTP/2 with TLS) — per §6. **Out of scope,
deliberately:** custom (non-HTTP) bindings (an ADR 0027-class sibling profile would be the
mechanism if one ever needs proof semantics); plain-HTTP deployments other than literal-loopback
development endpoints (which use the already-active
`bap-application-proof/local-loopback-http/1` profile; non-loopback plain HTTP has no proof
profile and no binding here — deployments use HTTPS); and push-notification webhooks, whose
agent→client direction is A2A's own `AuthenticationInfo` mechanism (A2A §4.3, §13.2) — §8 binds
the *configuration* of push notifications as request content, never the webhook delivery itself.

## 1. Normative sources

- A2A at `afda8316c64951a2ecb2a0d3d10867405d2b4095`
  ([a2aproject/A2A](https://github.com/a2aproject/A2A)), read first-hand from a pinned clone:
  `docs/specification.md` (§§3–5, 7–14 read end to end; §§1–2, 6, appendices at section level)
  and `specification/a2a.proto` (normative data model per A2A §1.4 — the spec text calls it
  `spec/a2a.proto`; the file sits at `specification/a2a.proto` in the repository; its package
  is `lf.a2a.v1`). OBSERVED.
- This repository at `fb83133`: `spec/bap-v1.md` (§§7, 10–14, 16, 17), `spec/bap-v2.md` (§4),
  `docs/design/registries.md`, `docs/design/ap2-interop-profile.md` (§6 cited, not restated),
  `docs/design/successor-major-charter.md`, `docs/adr/0010`, `docs/adr/0013`, `docs/adr/0027`,
  `docs/adr/0029` (cited), `docs/extensions/capability-authorization.mdx` (the MCP binding
  precedent). OBSERVED.
- gRPC over HTTP/2 protocol specification
  (`https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md`): requests are
  `:method POST` with `:path '/' Service-Name '/' {method name}` (Service-Name is the
  proto-package-qualified service name); the path grammar defines no query component. Pinned
  at commit `cf61c7d62a1a7f43b9d2ea6488186bc14fc41a8c` (2025-04-17, the last commit touching
  the document per the repository's commit history, read 2026-09-20; the bytes at that commit
  were read and the grammar verified at their lines 25–27 and 263). OBSERVED.

## 2. Terminology

- **Carriage** — where the grant and proof travel on a binding (HTTP header fields; gRPC
  metadata entries). Distinct from **binding surface** — what the proof's claims cryptographically
  name (`htm`, `htu`, `ba_inv`, `ba_op`, `ba_req`, `ath`, `nonce`; every claim the v1 proof
  table requires, placed by §§6–9).
- **Canonical request object** — the operation's request message as defined by the A2A proto
  (e.g. `SendMessageRequest`), reconstructed from the wire per the binding's own member-to-wire
  mapping (JSON-RPC `params`; REST body / path / query per A2A §11.5 and the proto's HTTP
  annotations; gRPC request message). Binding-independent by construction — with one recorded
  exception: default-valued scalar presence follows the binding's serialization (§8 rule 5), so
  the object's *shape* is binding-independent while presence of default-valued members is not.
- **Bounded projection** — the closed JSON value this profile defines each operation's request
  object to project to for `ba_req` (§8): value members as themselves, unbounded members as
  digests, always inside the v1 §17 ceilings.
- **Namespaced operation identity** — the `ba_op` spelling (§7).

## 3. The binding decision (recorded)

**Composition.** Negotiation at the A2A layer (§4); binding and carriage at the transport layer
(§§5–6); the canonical-object bounded projection in between (§8). Rejected alternatives,
recorded from the binding-decision options analysis: Option A (carriage inside the A2A data
model) — a digest-circularity exclusion taxing the exact-bytes digest discipline, task-history
persistence exposing proof material, and a second carriage surface still owed for the
non-message operations; Option B (pure HTTP layer) — no in-band discovery, no degradation hook,
and no declarable card scheme name. DERIVED (program record); the analysis itself is internal
provenance, and this section carries its operative conclusions.

## 4. Extension declaration, negotiation, and graceful degradation

An agent (A2A server) that consumes this binding declares it in its AgentCard:

```json
{
  "capabilities": {
    "extensions": [
      {
        "uri": "https://bounded-authority.io/extensions/a2a-capability-binding/v1",
        "description": "Bounded Authority Protocol capability grants + holder proofs on A2A requests",
        "required": false,
        "params": {}
      }
    ]
  }
}
```

- **Extension URI (INFERRED, decided).** `https://bounded-authority.io/extensions/a2a-capability-binding/v1`
  under the project-controlled domain (ADR 0013 confirmed ownership), in A2A's https identifier
  style (A2A §4.6 examples), versioned in the URI per A2A §4.6.3 — a breaking change to this binding
  gets a new URI. The URI is an identifier, not a promise of hosted content, and declares no
  A2A-venue status. The project's reversed-DNS prefix (`io.bounded-authority/…`, the MCP
  extension identifier's form) remains the fallback spelling if the owner prefers one namespace
  across venues; the https form is chosen here to match A2A's own examples.
- **Empty `params` (DECIDED).** The `AgentExtension.params` field carries an empty object,
  matching the MCP precedent (mdx §4.1): publishing the deployment's accepted contract-majors
  and suites is deferred to the reserved verifier discovery document, whose owner that content
  remains. This profile realizes no reserved purpose in a venue-native surface.
- **Client opt-in.** Clients declare use per request via the `A2A-Extensions` service parameter
  (A2A §3.2.6; HTTP header on the HTTP-based bindings, gRPC metadata) listing the extension URI
  (A2A §4.6.1).
- **`required` flag.** An agent that mandates the binding sets `required: true`; clients that
  do not support it then receive `ExtensionSupportRequiredError` semantics (A2A §3.3.4). Agents
  that merely accept it leave the flag false.
- **Graceful degradation (per the mdx §4.3 pattern).** If one party supports the binding and
  the other does not, the supporting party reverts to the card's declared `securitySchemes`
  posture — the authorization posture it applied before adding the binding. The capability
  layer never widens that posture.
- **Per-skill requirements (DECIDED).** This binding does not use per-skill
  `AgentSkill.security_requirements` (proto): the declaration is card-level. Per-skill
  requirements remain A2A's own mechanism; a future binding revision under a new extension URI
  may examine them.
- **Card integrity.** The AgentCard is unsigned by default; a substituted card could strip the
  extension declaration. Where the binding is load-bearing, deployments SHOULD verify a card
  signature (A2A §8.4) or pin the card out-of-band.
- **Undeclared carriage (DECIDED).** `BA-*` carriage arriving at a server that has not declared
  the extension, or on a request without the `A2A-Extensions` opt-in, is not processed — the
  headers are ignored, the request proceeds under the card's declared posture. The negotiated
  contract governs; undeclared proofs are neither a bypass nor an error (A2A's own
  forward-compatibility posture — implementations SHOULD ignore unrecognized fields, A2A §5.7 —
  is followed). Consequence, stated plainly: the opt-in is client-controlled, so a deployment
  that relies on this binding to narrow its authorization posture MUST either set
  `required: true` or enforce the capability check in its own authorization layer — otherwise
  the narrowing is client-optional and a holder holding both a narrow grant and broader
  credentials can simply omit the opt-in.

## 5. Carriage

The grant and proof ride as one value each, outside the request body (the RFC 9449 structure —
the proof signs the request; the request does not contain the proof):

| Binding | Grant carriage | Proof carriage |
|---|---|---|
| JSON-RPC (A2A §9) | HTTP header `BA-Grant` | HTTP header `BA-Proof` |
| HTTP+JSON/REST (A2A §11) | HTTP header `BA-Grant` | HTTP header `BA-Proof` |
| gRPC (A2A §10) | metadata `ba-grant` | metadata `ba-proof` |

- Values are the compact-JWS strings (base64url ASCII; header-safe; no folding, single value
  each).
- **Naming (INFERRED, decided).** `BA-Grant` / `BA-Proof` (gRPC lowercases per its metadata
  convention, A2A §10.2) are modeled on the registries' prefix convention, extended to a
  surface — HTTP header field names — that the registries do not govern (the `ba_`/`ba+`
  convention scopes claims and media-type suffixes). They stay clear of the `a2a-` prefix,
  which A2A reserves for its own spec-defined service parameters (A2A §3.2.6 — A2A states its
  own side; the stay-clear rule is this program's inference). These names are unregistered; an
  eventual IANA header registration would follow the template path A2A itself uses for its
  headers (A2A §14.2) and is outside this slice.
- **Size guidance (INFERRED).** The v1 compact-input ceiling is 65,536 bytes; common server
  header budgets are smaller. Issuers binding A2A SHOULD keep grants comfortably inside the
  deployment's carriage budget (as guidance: ≤ 8 KiB of total `BA-*` carriage per request); a
  grant too large for the carrier fails closed at the carrier, never at the verifier.

## 6. Proof binding — `htm`, `htu`

Every proof is the published `dpop+jwt` profile with unchanged claims and semantics
(`spec/bap-v1.md` §11); `htm`/`htu` bind the concrete transport request:

| Binding | `htm` | `htu` |
|---|---|---|
| JSON-RPC | `POST` | normalized HTTPS URL of the selected `AgentInterface` entry |
| HTTP+JSON/REST | the verb of the route actually used, per the proto's HTTP annotations (the normative source, A2A §1.4) — note a divergence in the A2A repository itself for `SubscribeToTask`: the annotations say `GET /tasks/{id=*}:subscribe` while the specification text's §11.3.2 and §5.3 tables say `POST`; this binding follows the proto annotations and records the divergence | normalized HTTPS URL of the interface entry + the route path actually used (bare or `/{tenant}/…` additional route); no query — A2A §11.5 query parameters are covered by the projection (§8) |
| gRPC | `POST` | `https://{authority}/lf.a2a.v1.A2AService/{Method}` — `:method POST` and the `/Service-Name/{method}` path are the gRPC over HTTP/2 specification's grammar (§1, pinned); the interface entry declares the authority as `hostname:port`; port 443 drops, nondefault ports keep, per v1 §13 |

- URI normalization is v1 §13 verbatim (HTTPS-only, query-free, pre-normalized, no network
  work). The binding's functional equivalence (A2A §5.1) holds at the operation level: the
  projection (§8 — modulo default-valued scalar presence, which follows the binding's
  serialization per its rule 5) and `ba_op` (§7) are binding-independent, while the proof bytes
  are per-binding — a proof minted for one binding does not verify at another, the correct
  fail-closed direction.
- Plain-HTTP (non-production) deployments cannot carry the HTTPS-only `dpop+jwt` profile;
  literal-loopback development endpoints use the already-active
  `bap-application-proof/local-loopback-http/1` profile (ADR 0027; registries) with its nonce
  requirement and `127.0.0.1`/`[::1]` host discipline. Custom (non-HTTP) bindings are out of
  scope; if one ever needs proof semantics, an ADR 0027-class sibling profile is the mechanism,
  not a redefinition of `dpop+jwt`.

## 7. Operation vocabulary — `ba_op`

The registries fix the namespace discipline: bare operation names are deployment-scoped;
cross-vendor interoperable vocabularies use reverse-DNS prefixes. An A2A binding's operation
vocabulary is cross-vendor by construction.

**Decision (INFERRED):** `ba_op` is spelled `io.bounded-authority/a2a/{Method}` — the
project-controlled reversed-DNS prefix (available now; the vocabulary definition is this
binding's) over the canonical A2A method name (the PascalCase identity shared by JSON-RPC and
gRPC; REST routes are binding framing, not operation identity). An A2A-domain prefix would
presume upstream coordination this program does not assume; if A2A later standardizes an
operation registry, a binding revision under a new extension URI can re-home. The longest spellings
(`io.bounded-authority/a2a/CreateTaskPushNotificationConfig` and
`io.bounded-authority/a2a/DeleteTaskPushNotificationConfig`) are 57 printable-ASCII bytes each,
inside the 128-byte ceiling.

| `ba_op` | Canonical method |
|---|---|
| `io.bounded-authority/a2a/SendMessage` | SendMessage (also SendStreamingMessage's request shape — see §8) |
| `io.bounded-authority/a2a/SendStreamingMessage` | SendStreamingMessage |
| `io.bounded-authority/a2a/GetTask` | GetTask |
| `io.bounded-authority/a2a/ListTasks` | ListTasks |
| `io.bounded-authority/a2a/CancelTask` | CancelTask |
| `io.bounded-authority/a2a/SubscribeToTask` | SubscribeToTask |
| `io.bounded-authority/a2a/CreateTaskPushNotificationConfig` | CreateTaskPushNotificationConfig |
| `io.bounded-authority/a2a/GetTaskPushNotificationConfig` | GetTaskPushNotificationConfig |
| `io.bounded-authority/a2a/ListTaskPushNotificationConfigs` | ListTaskPushNotificationConfigs |
| `io.bounded-authority/a2a/DeleteTaskPushNotificationConfig` | DeleteTaskPushNotificationConfig |
| `io.bounded-authority/a2a/GetExtendedAgentCard` | GetExtendedAgentCard |

`SendMessage` and `SendStreamingMessage` share one request message but are distinct operations
(distinct `ba_op`, distinct `htm`/`htu` on the REST binding's `/message:send` vs
`/message:stream`) — the table gives each its own row.

## 8. The bounded cast-arguments projection

`ba_req` is the published v1 construction —
`base64url(SHA-256("BAP1-REQUEST\0" || JCS([operation, typed(cast_arguments)])))` — with
`operation` the namespaced `ba_op` string and `cast_arguments` the projection defined here.

**Rules (INFERRED; every ceiling cited is v1 §17, OBSERVED):**

1. **Value members project as themselves:** identifiers, ProtoJSON enum strings, booleans,
   integers, and arrays of bounded strings. One timestamp rendering is fixed: timestamps
   project as `YYYY-MM-DDTHH:mm:ss.sssZ` — millisecond precision, zero-filled, with
   sub-millisecond digits truncated toward zero — regardless of source precision
   (A2A §5.6.1 permits omitted or zero-filled fractions and makes millisecond precision a
   SHOULD; the projection picks one spelling so `ba_req` is deterministic).
2. **Unbounded members project as digests.** `digest(v) = base64url(SHA-256(ASCII("ba-a2a-digest\0") || JCS(typed(v))))`,
   where `typed(v)` is the v1 §7 tagged projection of the member's decoded JSON value — the
   same integer/float tag preservation the outer construction uses, kept inside digested
   members. The label `ba-a2a-digest\0` is this binding's internal projection construction —
   deliberately outside the `ba_`/`ba+` registry prefixes, which govern claims, `typ` values,
   and media types, not projection-internal separators. Digesting is streaming work outside
   the bounded decoder; the resulting 43-character string is a bounded member.
3. **Parts project as a digest array:** `message.parts` projects to an array of
   `digest(part)`, one per part, in source order — part content is bound by digest, never by
   inclusion. A message with more parts than the 256-item array ceiling has no representable
   projection (fail closed).
4. **`tenant` is covered by every projection, including its declared absence:** the string
   when the selected `AgentInterface` declares one; JSON `null` when it does not (A2A §8.3.2
   rule 4 directs omission on the wire — the projection makes the absence explicit so a proof
   minted for one tenant cannot be replayed at another sharing the endpoint).
5. **The projection is over the received serialization — except where another rule fixes a
   canonical rendering.** Rules 1 (timestamps) and 4 (tenant absence) re-render canonically;
   everything else follows the received form. On the JSON bindings, a body member projects as
   present exactly when the received JSON carries it (a serialized `contextId: ""` and an
   omitted `contextId` are distinct wire states, projected distinctly). On REST path- and
   query-borne members (A2A §11.5), a member projects as present exactly when the path segment
   or query parameter is present on the request — an empty query value projects as the empty
   string, not as absence. On gRPC, the canonical object is the request message's ProtoJSON
   form (default-suppressing), reconstructed identically by producer and verifier. A2A §5.7's
   presence semantics (the `optional` keyword) govern the wire form; the projection never
   re-serializes through language objects, so proto3 default/absent ambiguity cannot diverge
   the digest.
6. **Transport framing does not project:** the JSON-RPC wrapper (`jsonrpc`, `id`, `method`),
   REST route and query framing, and gRPC message framing are reconstruction inputs, not
   members. The projection is over the canonical request object.
7. **The projection is closed and fail-closed against the ceilings.** Members not named in the
   table below do not project and are therefore outside `ba_req` (A2A's forward-compatibility
   rule — implementations SHOULD ignore unrecognized fields, A2A §5.7 — is respected; the
   binding covers the schema-defined surface). And every member carries the ceilings: any
   string member beyond 8,192 bytes (including `pageToken`, `url`, `token`, and every
   extension URI or mode string), any array beyond 256 items (`extensions`,
   `referenceTaskIds`, `acceptedOutputModes` included), or a projection whose typed form
   exceeds any v1 §17 maximum has no representable projection — verification fails closed. The
   ceilings measure the typed projection (each scalar costs three nodes under the v1 tagged
   form), so the worst representable case — the largest table row plus four 256-item
   bounded-string arrays — is ≈3,100 nodes against the 4,096-node ceiling: inside with
   headroom, and closed beyond it.

**Per-operation projection table** (member names in ProtoJSON camelCase per A2A §5.5;
timestamps per rule 1; all shapes OBSERVED from the proto):

| Operation | Value members | Digest members |
|---|---|---|
| SendMessage / SendStreamingMessage | `tenant`; `message.{messageId, contextId, taskId, role, extensions, referenceTaskIds}`; `configuration.{acceptedOutputModes, returnImmediately, historyLength}` | `message.parts` → digest array (rule 3); `message.metadata`; `metadata`; `configuration.taskPushNotificationConfig` |
| GetTask | `tenant`, `id`, `historyLength` | — |
| ListTasks | `tenant`, `contextId`, `status`, `pageSize`, `pageToken`, `historyLength`, `statusTimestampAfter`, `includeArtifacts` | — |
| CancelTask | `tenant`, `id` | `metadata` |
| SubscribeToTask | `tenant`, `id` | — |
| CreateTaskPushNotificationConfig | `tenant`, `id`, `taskId`, `url`, `token` | `authentication` |
| GetTaskPushNotificationConfig | `tenant`, `taskId`, `id` | — |
| ListTaskPushNotificationConfigs | `tenant`, `taskId`, `pageSize`, `pageToken` | — |
| DeleteTaskPushNotificationConfig | `tenant`, `taskId`, `id` | — |
| GetExtendedAgentCard | `tenant` | — |

Absent members project as absent per rule 5 (received-serialization presence); the
projection object's member count stays inside the 64-member ceiling by construction (largest
table row: 10 value members + 4 digest members).

## 9. Grant audience and nonce posture

- **Audience (INFERRED, guidance).** Grant `aud` names the target A2A server identity.
  Deployments SHOULD set it to the normalized HTTPS URL of the selected `AgentInterface`
  entry — for gRPC entries, the `hostname:port` form converted per §6's rule
  (`https://{authority}`) before use — or to a deployment-defined agent identity, and fix the
  verifier's `expected.audience` out-of-band. Exact audience match is required by the profile
  (`REQ1-VERIFY-grant-exact`); tenant multiplexing behind one endpoint is covered by the
  projection (§8 rule 4), not by `aud`.
- **`ba_inv` (INFERRED, decided).** Each proof carries a fresh lowercase RFC 4122 UUID minted
  by the holder for that A2A request — one proof per request, one `ba_inv` per proof, never
  derived from `messageId`/`taskId` (which the issuer did not bind and which may repeat across
  bindings). Correlating `ba_inv` into the consumption row is the runtime's responsibility,
  not the verifier's (verification is not authority).
- **Nonce (INFERRED, posture).** Both published nonce modes are legal under this binding.
  Not-required mode is this profile's default posture. A server electing nonce-required mode
  needs a deployment-defined nonce distribution channel outside the A2A wire (A2A defines no
  nonce surface); the nonce is then bound per proof as published (`REQ1-VERIFY-nonce-mode`).
  Replay reservation in all modes is the server's state, never the verifier's.
- **Times.** Proofs are per-request (`jti`, `iat` fresh; maximum age 300 s, skew ≤ 60 s per the
  profile) — one proof per A2A request, no session credential.

## 10. Selector expressiveness boundary

Selector paths traverse objects only and never index arrays (`spec/bap-v1.md` §12; v2 §4
identical). Under this binding, selectors can bound the request envelope — `tenant`,
`message.taskId`, `message.contextId`, configuration members, list filters — but no selector
reaches an individual part or element of a repeated field. Part content integrity rests on the
per-part digests inside `ba_req` (§8 rule 3). A v1 grant expresses exact-value and enumerated
bounds; a v2 grant adds `lte`/`gte` on numeric members (same-tag, inclusive). Cumulative
budgets remain outside the selector algebra in both majors and route to the issuer-attestation
/ runtime-accounting posture (ADR 0029) — unchanged by this binding.

## 11. `TASK_STATE_AUTH_REQUIRED` composition

A2A §7.6.3 recommends — as a SHOULD, and specifically for *in-band* credential exchange; the
out-of-band default it prefers is not covered by the sentence at all — that credentials be
"bound to the agent which originated the request." On this program's reading of that phrase,
that agent is the one that raised the state and will spend the credential — the opposite
holder position from this binding's client-held, client→server proof. The intersection with
BAP is therefore issuance-shaped, not presentation-shaped: an issuer may mint a separate grant
naming the receiving agent as holder, for the downstream resource that triggered the state;
that grant is presented under whatever binding governs the agent's downstream call, not under
this one, and is one grant per hop from the issuer. Passing a client-held grant onward is
delegation-shaped and routes per §12. No in-band grant-forwarding mechanism is defined here;
the holder-position argument above rests on a conditional recommendation, not a normative A2A
rule.

## 12. Delegation routing and UCP

- **Delegation.** This binding covers exactly one hop of
  published single-holder semantics: issuer → holder (A2A client agent) → verifier (A2A server
  or its authorization layer). Attenuation is available only as issuance-time narrowness. Any
  requirement that a downstream agent hold a derivative of an upstream grant — sub-agent
  chains, narrowed re-issuance by the holder, in-band forwarding — is BAP delegation, reserved
  to the successor contract-major (ADR 0010; charter § Delegation with attenuation), and is
  recorded here as a dependency of that program: when it activates, it owes an A2A-specific
  composition note for how a delegated chain rides this binding. Any requirement naming the
  human principal on whose behalf the client acts is the reserved on-behalf-of surface; both it
  and the delegation names stay at the reserved-registry-row level, enumerated only by §14's
  gate sentence.
- **UCP.** Outside this binding decision's scope; a separately-owned open
  question whose precondition is pinning and reading a UCP source first. Nothing in this
  profile designs a UCP riding point. That question is now closed by
  [ADR 0034](../adr/0034-ucp-riding-point-scoping.md): the riding point is transport-composed,
  and this profile covers UCP's A2A transport as-is for deployments speaking A2A 1.0.

## 13. Verification posture and vectors

- The binding adds no BAP code and no new wire surface: verification is the published pure
  functions over the deployment's expected context (trusted keys, audience per §9, evaluation
  time, nonce mode). Facts are unchanged — `GrantFacts` / `EnvelopeFacts` with
  `authorization: :not_evaluated`; no decision, no receipt.
- Conformance vectors for the projection (cases pinning the §8 table, the digest-member
  boundary, the tenant-absence shape, and the §6 per-binding `htu` spellings) are follow-on
  certified-corpus work. No interop claim will rest on self-round-trips; a cross-protocol claim
  would require an independent implementation exercising both sides.
- The ES256 suite is orthogonal: this binding is suite- and major-agnostic — it
  binds whatever contract-major the deployment's verifier accepts, under ADR 0009's succession
  rules unchanged.

## 14. Disclosure-gate compliance

The gate: nothing beyond published specification text enters this repository until lifted — no
`ba_dlg`/`ba_obo`/`ba_offline`/`ba_sut`/detached-profile activation or documentation beyond the
existing reserved registry rows. Compliance read of this document:

- Reserved mechanism names appear only inside this section's gate sentence — never designed,
  specified, or promised.
- The reserved verifier discovery document stays untouched, its purpose unrealized here (the
  empty-`params` posture of §4); the grant status-check profile is not referenced beyond this
  sentence.
- No cumulative-budget material is designed (ADR 0029 governs; §10 cites it).
- No forward promise of submission, upstream contribution, or runtime compatibility appears
  (§0's non-claims govern the whole document).

## 15. Open questions

1. A venue-facing A2A extension document (the `.mdx` analog of the MCP extension drafts) — owner-gated,
   not part of this decision's scope; this repository's design spec is the current deliverable.
2. Eventual IANA registration of the carriage header names (template path per A2A §14.2) —
   outside this slice; coordinates with the BAP-12 row's claims/media-type filings, which are
   separate registries.
3. Projection and `htu` conformance vectors (§13).
4. Real-substrate runtime evidence (an actual A2A server verifying a proof) — a future
   implementation slice's work; this document is design-only.
