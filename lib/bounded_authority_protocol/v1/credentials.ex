defmodule BoundedAuthorityProtocol.V1.Credentials do
  @moduledoc """
  Closed raw compact grant and proof credentials.

  The raw grant and proof compacts exactly as received.

  ## Fields

  * `grant` - the exact grant compact bytes as received. Redacted by `inspect/2`.
  * `proof` - the exact proof compact bytes as received. Redacted by `inspect/2`.
  """

  @enforce_keys [:grant, :proof]
  defstruct @enforce_keys

  @typedoc "Raw credentials for the façade's `check_envelope/2` (for example `BoundedAuthorityProtocol.V1.check_envelope/2`)."
  @type t :: %__MODULE__{grant: binary(), proof: binary()}
end

defimpl Inspect, for: BoundedAuthorityProtocol.V1.Credentials do
  # Redacts credential-bearing fields so routine logging never prints them.
  def inspect(%BoundedAuthorityProtocol.V1.Credentials{grant: _grant, proof: _proof}, _options) do
    Inspect.Algebra.string(
      "#BoundedAuthorityProtocol.V1.Credentials<" <>
        "grant: :redacted, " <>
        "proof: :redacted" <>
        ">"
    )
  end
end
