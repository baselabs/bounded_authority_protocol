# Local-loopback HTTP profile requirement map

This map traces every normative `REQ-LLH1-*` requirement in
[`spec/bap-local-loopback-http-v1.md`](../../spec/bap-local-loopback-http-v1.md) to executable
evidence or an explicit downstream/release gate. The certified profile corpus is revision 1 at
`priv/conformance/application-profiles/local-loopback-http/v1`.

| Requirements | Evidence | Status |
|---|---|---|
| `CORE-compose-v1`, `CORE-profile-identity`, `HEADER-closed-set`, `HEADER-signed-identity` | `proof-cases.json`; five SDK corpus consumers; exact producer/assembly bytes | populated |
| `CORE-cross-profile-reject`, `CORE-no-inference-fallback` | local, standard, and unknown `typ` cases; separate public namespaces; architecture export/import locks | populated |
| `CLAIM-closed-required`, `CLAIM-grant-major`, `CLAIM-nonce-required`, `CLAIM-v1-bindings` | missing/wrong nonce, valid signed envelope, and complete legacy BAP1 corpus | populated |
| `URI-canonical`, `URI-http`, `URI-exact-hosts`, `URI-host-reject-list`, `URI-port`, `URI-path`, `URI-reject-list`, `URI-pre-normalized` | 36 language-neutral URI cases run by all five implementations | populated |
| `URI-no-network-proxy` | pure-library architecture gate plus URI implementations with no I/O imports | populated |
| `API-complete`, `API-return-shape`, `API-no-signer`, `API-assembly-revalidate`, `API-symmetry`, `API-facts` | five separately named public surfaces per implementation; corpus producer/assembly/decode/envelope checks; existing redacted fact-shape gates | populated |
| `CONFORMANCE-complete`, `CONFORMANCE-sdks`, `CONFORMANCE-no-drift` | certified profile index plus Elixir/TypeScript/Python/Rust/Go consumers; unchanged complete 283-case BAP1 suite is a release blocker | populated |
| `CONFORMANCE-real-network`, `HOST-direct-target`, `HOST-one-profile` | `mix local_loopback_http.verify`: real `127.0.0.1` and `::1` HTTP listeners, fresh in-memory keys, direct listener/request target derivation, secret-free receipt | populated |
| `SECURITY-honest-scope` | normative security section, README, and threat model state that loopback HTTP is neither TLS nor process isolation | populated |
| `IANA-template` | exact active registry entry plus machine-readable and rendered RFC 6838 templates; filing remains externally gated | populated |
| `HOST-replay-trust` | Public verifier checks the required nonce but owns no state. BA-37 must prove reservation before effect in the adopting authority runtime. | downstream gate |
| `RELEASE-immutable` | Requires the exact reviewed package and corpus identity to be published before BA-37 adopts it. Publication is not authorized by design approval. | release gate |

“Populated” means the repository contains executable evidence for the public-library obligation. It
does not claim live replay reservation, revocation, trust selection, or a business effect; those
remain downstream authority-host responsibilities.
