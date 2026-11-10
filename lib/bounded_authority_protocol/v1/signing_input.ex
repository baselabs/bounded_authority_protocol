defmodule BoundedAuthorityProtocol.V1.SigningInput do
  @moduledoc """
  Closed deterministic standard-JWS signing input.

  Sign `message` with the matching private key outside this library, then pass the signing input and
  the raw signature to the major's `assemble_compact/3` (for example `BoundedAuthorityProtocol.V1.assemble_compact/3`).

  ## Fields

  * `kind` - which compact this input builds (`:grant`, `:proof`, `:local_loopback_http_proof`,
    `:boundary_anchor`, `:key_transition`, `:role_attestation` or `:content_assertion`).
  * `protected_segment` - the base64url-encoded JCS protected header. Redacted by `inspect/2`.
  * `payload_segment` - the base64url-encoded JCS payload. Redacted by `inspect/2`.
  * `message` - the exact RFC 7515 signing input `protected_segment <> "." <> payload_segment`.
    Redacted by `inspect/2`.
  """

  @enforce_keys [:kind, :protected_segment, :payload_segment, :message]
  defstruct @enforce_keys

  @typedoc "The exact bytes a signer signs."
  @type t :: %__MODULE__{
          kind:
            :grant
            | :proof
            | :local_loopback_http_proof
            | :boundary_anchor
            | :key_transition
            | :role_attestation
            | :content_assertion,
          protected_segment: binary(),
          payload_segment: binary(),
          message: binary()
        }
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.SigningInput do
  # Redacts credential-bearing fields so routine logging never prints them.
  def inspect(
        %BoundedAuthorityProtocol.V1.SigningInput{
          kind: kind,
          protected_segment: _protected_segment,
          payload_segment: _payload_segment,
          message: _message
        },
        _options
      ) do
    Inspect.Algebra.string(
      "#BoundedAuthorityProtocol.V1.SigningInput<" <>
        "kind: " <>
        Kernel.inspect(kind) <>
        ", " <>
        "protected_segment: :redacted, " <>
        "payload_segment: :redacted, " <>
        "message: :redacted" <>
        ">"
    )
  end
end
