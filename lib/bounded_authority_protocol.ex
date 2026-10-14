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
    * `BoundedAuthorityProtocol.Ed25519` and `BoundedAuthorityProtocol.Es256`: the signature
      rules each suite's verification and producer surfaces share.

  Every verification function returns redacted facts or exactly `{:error, :invalid}`; a
  result is never an authorization decision. Start with the getting-started guide.
  """
end
