defmodule BoundedAuthorityProtocol.V1.EncodedConsumptionEntry do
  @moduledoc """
  Exact canonical consumption row bytes and domain-separated row hash.

  ## Fields

  * `bytes` - the exact canonical JCS row bytes, at most `chain_row_bytes` (4,096).
  * `hash` - the raw 32-byte domain-separated hash of `bytes` under the contract-major that encoded
    it; the next row's `previous_hash`.
  """

  @enforce_keys [:bytes, :hash]
  defstruct @enforce_keys

  @typedoc "One encoded consumption-chain row."
  @type t :: %__MODULE__{bytes: binary(), hash: binary()}
end
