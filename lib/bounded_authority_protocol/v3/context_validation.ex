defmodule BoundedAuthorityProtocol.V3.ContextValidation do
  @moduledoc false

  # Suite-bound context validation. Only `historical_key/2` carries a
  # suite-bound constant (the 65-byte uncompressed-SEC1 raw public key); every
  # other validator is version-neutral and single-sources from the v1 module,
  # which hard-codes the Ed25519 width and is frozen.

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ContextValidation, as: SharedValidation
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey

  @public_key_bytes 65

  defdelegate expected_chain(expected, bounds), to: SharedValidation
  defdelegate expected_anchor(expected, bounds), to: SharedValidation
  defdelegate expected_transition(expected, bounds), to: SharedValidation
  defdelegate distinct_fingerprints(current, next, bounds), to: SharedValidation

  @spec historical_key(HistoricalPublicKey.t(), Bounds.t()) :: :ok | {:error, :invalid}
  def historical_key(%HistoricalPublicKey{} = key, bounds) do
    if valid_key_id?(key.key_id, bounds) and is_binary(key.public_key) and
         byte_size(key.public_key) == @public_key_bytes and
         valid_time?(key.valid_from, bounds) and
         valid_before?(key.valid_before, key.valid_from, bounds) do
      :ok
    else
      {:error, :invalid}
    end
  end

  def historical_key(_key, _bounds), do: {:error, :invalid}

  defp valid_time?(value, bounds),
    do:
      is_integer(value) and value >= -bounds.integer_magnitude and
        value <= bounds.integer_magnitude

  defp valid_before?(:unbounded, _valid_from, _bounds), do: true

  defp valid_before?(valid_before, valid_from, bounds),
    do: valid_time?(valid_before, bounds) and valid_before > valid_from

  defp valid_key_id?(value, bounds),
    do:
      is_binary(value) and byte_size(value) >= 1 and byte_size(value) <= bounds.kid_bytes and
        ascii_key_id?(value)

  defp ascii_key_id?(<<>>), do: true

  defp ascii_key_id?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?-, ?., ?_, ?~],
       do: ascii_key_id?(rest)

  defp ascii_key_id?(_value), do: false
end
