# Notebook index

Every notebook installs exactly `bounded_authority_protocol` 1.0.0, generates its own
demonstration keys, asserts success and refusal, and persists only safe semantic outputs.
The runner executes each in a fresh VM in both local-checkout and published-Hex modes.

| Journey | Focus |
|---|---|
| [Core envelope verification](../notebooks/bap-walkthrough.livemd) | Grant, holder proof, request binding, tampering and freshness |
| [Contract-major 2 ranges](../notebooks/v2-ranges.livemd) | Inclusive endpoints, integer/float tags and invalid selectors |
| [Contract-major 3 ES256](../notebooks/v3-es256.livemd) | P-256 signing, DER conversion, low S and cross-profile refusals |
| [Service integration](../notebooks/service-integration.livemd) | Trusted-key rotation and grant-lifetime execution replay retention |
| [Local loopback](../notebooks/local-loopback.livemd) | Explicit HTTP profile, literal addresses and exact server nonce |
| [Role attestations](../notebooks/role-attestations.livemd) | Subject binding, self-attestation refusal and attestor windows |
| [Content lineage](../notebooks/content-lineage.livemd) | Exact content digests, verified generations and successor consistency |
| [Chains and archives](../notebooks/chains-and-archives.livemd) | Expected boundaries, historical-key transitions and immutable object identity |
| [Advanced strict crypto](../notebooks/strict-crypto.livemd) | Certified Ed25519 forgery controls and enrollment subgroup checks |

The launch links open the existing 1.0.0 notebooks at the release tag. New focused files have
direct import instructions until a maintainer release includes their paths. The exact released
walkthrough does not cover contract-major 2 ranges. A source change cannot alter an already-published tag.
