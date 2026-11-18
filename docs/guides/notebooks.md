# Notebook index

Each notebook has a setup cell, then one explained step per code cell. Top-level result
matches assert success and refusal; every cell has a nonempty persisted output checked by
the runner. The output count includes setup. No notebook starts a process, opens a listener,
creates an ETS table, or writes a file; demonstration keys remain in memory.

Every notebook installs exactly `bounded_authority_protocol` 1.0.0, generates its own
demonstration keys, asserts success and refusal, and persists only safe semantic outputs.
Qualification runs each in a fresh VM against this checkout (`--local`). The publication
workflow runs them unchanged against the exact Hex release right after each upload
(`--published`), in a job that holds no key.

| Journey | Focus | Outputs |
|---|---|---|
| [Core envelope verification](../notebooks/bap-walkthrough.livemd) | Grant, holder proof, request binding, tampering and freshness | 10 |
| [Contract-major 2 ranges](../notebooks/v2-ranges.livemd) | Inclusive endpoints, integer/float tags and invalid selectors | 7 |
| [Contract-major 3 ES256](../notebooks/v3-es256.livemd) | P-256 signing, DER conversion, low S and cross-profile refusals | 9 |
| [Service integration](../notebooks/service-integration.livemd) | Trusted-key rotation and grant-lifetime execution replay retention | 16 |
| [Local loopback](../notebooks/local-loopback.livemd) | Explicit HTTP profile, literal addresses and exact server nonce | 7 |
| [Role attestations](../notebooks/role-attestations.livemd) | Subject binding, self-attestation refusal and attestor windows | 8 |
| [Content lineage](../notebooks/content-lineage.livemd) | Exact content digests, verified generations and successor consistency | 10 |
| [Chains and archives](../notebooks/chains-and-archives.livemd) | Expected boundaries, historical-key transitions and immutable object identity | 16 |
| [Advanced strict crypto](../notebooks/strict-crypto.livemd) | Certified Ed25519 forgery controls and enrollment subgroup checks | 10 |

Import a current `.livemd` file into Livebook and choose **Run all** to use these steps.
The launch links preserve the earlier notebooks at the immutable 1.0.0 release tag. That
release has no focused range notebook; use the current file for contract-major 2 ranges.
