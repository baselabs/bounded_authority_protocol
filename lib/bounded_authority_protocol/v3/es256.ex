defmodule BoundedAuthorityProtocol.V3.Es256 do
  @moduledoc false

  # The `BAP3-ES256-SHA256` suite's internal entry points. The public
  # `BoundedAuthorityProtocol.Es256` owns every ES256 rule: the raw `r || s`
  # canonicality rule (`0 < r < n`, `0 < s <= n/2`), public-key acceptance, and
  # strict verification. This module only adapts them to the codecs' shapes.

  alias BoundedAuthorityProtocol.Es256

  @doc false
  @spec valid_raw_signature?(binary()) :: boolean()
  def valid_raw_signature?(signature), do: Es256.canonical_signature?(signature)

  # The producer-surface form of the rule (erratum 3): compact assembly and
  # anchored-export encoding refuse a non-canonical signature with the closed
  # error and never rewrite its bytes.
  @doc false
  @spec canonical_signature(binary()) :: :ok | {:error, :invalid}
  def canonical_signature(signature) do
    if Es256.canonical_signature?(signature), do: :ok, else: {:error, :invalid}
  end

  @doc false
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(message, signature, public_key),
    do: Es256.verify_strict(message, signature, public_key)
end
