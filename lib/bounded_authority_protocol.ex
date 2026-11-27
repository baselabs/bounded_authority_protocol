defmodule BoundedAuthorityProtocol do
  @moduledoc """
  Deterministic protocol verification for cryptographically bounded
  proof-of-possession authority.

  This module holds no functions. Every protocol behavior lives in an explicitly named
  namespace; there is no implicit latest profile and no unversioned façade:

    * `BoundedAuthorityProtocol.V1`, `BoundedAuthorityProtocol.V2`, and
      `BoundedAuthorityProtocol.V3`: contract-majors 1, 2, and 3 (grants, holder proofs,
      consumption chains, boundary anchors, key transitions, and anchored exports), with
      public submodules such as `BoundedAuthorityProtocol.V1.Json` and
      `BoundedAuthorityProtocol.V1.Base64Url`.
    * `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1`: the byte-distinct
      literal-loopback HTTP proof profile.
    * `BoundedAuthorityProtocol.RoleAttestation.V1` and
      `BoundedAuthorityProtocol.ContentAssertion.V1`: the standalone sibling attestation
      profiles.
    * `BoundedAuthorityProtocol.HolderCustodyAttestation.V1`: the source candidate for describing
      how a holder key is held.
    * `BoundedAuthorityProtocol.Ed25519` and `BoundedAuthorityProtocol.Es256`: the signature
      rules each suite's verification and producer surfaces share.

  Credential and evidence verifiers return `{:ok, facts}` or `{:error, :invalid}`; facts have
  redacted inspection. `BoundedAuthorityProtocol.ContentAssertion.V1.verify_successor/3` instead
  checks consistency between supplied facts and returns `:ok` or `{:error, :invalid}` without
  establishing their provenance. Public signature and key predicates return booleans. No result
  is an authorization decision. Already-trusted public keys and time are explicit inputs; this
  package has no private-key access or custody. `BoundedAuthorityProtocol.V1.Bounds.maximum/0`
  returns its struct directly; the conformance CLI returns an integer exit status, `0`, `1` or
  `2`. See the API result matrix and start with the getting-started guide.
  """
end
