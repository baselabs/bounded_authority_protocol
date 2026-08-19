defmodule BoundedAuthorityProtocol.V1 do
  @moduledoc "Explicit entry point for the immutable v1 wire profile."

  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.KeyLocator
  alias BoundedAuthorityProtocol.V1.RequestDigest
  alias BoundedAuthorityProtocol.V1.Runtime
  alias BoundedAuthorityProtocol.V1.SigningInput

  @doc """
  Parses only the protected grant header and returns its untrusted `kid` hint.

  The complete compact input is bounded. Payload and signature segments are not decoded,
  interpreted, or independently size-checked.
  """
  @spec untrusted_key_locator(binary(), Bounds.t() | map()) ::
          {:ok, KeyLocator.t()} | {:error, :invalid}
  def untrusted_key_locator(compact, limits \\ %{})

  def untrusted_key_locator(compact, limits) when is_binary(compact) do
    with {:ok, bounds} <- Bounds.coerce(limits),
         true <- byte_size(compact) <= bounds.compact_bytes,
         [protected, _payload, _signature] <- :binary.split(compact, <<".">>, [:global]),
         true <- byte_size(protected) <= bounds.encoded_segment_bytes,
         {:ok, header_bytes} <- Base64Url.decode(protected, bounds),
         {:ok, {:object, members}} <- Json.decode(header_bytes, bounds),
         {:ok, kid} <- closed_header(members, nil, nil, nil),
         true <- valid_kid?(kid, bounds.kid_bytes) do
      {:ok, %KeyLocator{kid: kid, trust: :not_evaluated}}
    else
      _failure -> {:error, :invalid}
    end
  end

  def untrusted_key_locator(_compact, _limits), do: {:error, :invalid}

  @doc "Builds the deterministic standard-JWS grant signing input."
  defdelegate grant_signing_input(grant, limits), to: Runtime

  @doc "Builds the deterministic standard-JWS holder-proof signing input."
  defdelegate proof_signing_input(proof, limits), to: Runtime

  @doc "Encodes one exact canonical consumption-chain row."
  defdelegate encode_consumption_entry(entry, limits), to: Runtime

  @doc "Checks a raw nonempty consumption-chain range against mandatory caller boundaries."
  defdelegate check_chain(input, expected), to: Runtime

  @doc "Builds the deterministic standard-JWS boundary-anchor signing input."
  defdelegate boundary_anchor_signing_input(anchor, limits), to: Runtime

  @doc "Builds the deterministic standard-JWS historical-key-transition signing input."
  defdelegate key_transition_signing_input(transition, limits), to: Runtime

  @doc "Frames an exact deterministic anchored export after semantic validation."
  defdelegate encode_anchored_export(input, expected), to: Runtime

  @doc "Assembles a validated signing input and raw Ed25519 signature at profile maxima."
  @spec assemble_compact(SigningInput.t(), binary()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature),
    do: assemble_compact(signing_input, signature, %{})

  @doc "Assembles a validated signing input and raw Ed25519 signature under caller bounds."
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature, limits),
    do: Runtime.assemble_compact(signing_input, signature, limits)

  @doc "Boundedly decodes a raw compact grant without evaluating trust."
  defdelegate decode_grant(compact, limits), to: Runtime

  @doc "Boundedly decodes a raw compact proof without evaluating trust."
  defdelegate decode_proof(compact, limits), to: Runtime

  @doc "Verifies one raw compact grant against caller-supplied trust and expected context."
  defdelegate verify_grant(compact, trusted_issuer, expected_grant), to: Runtime

  @doc "Verifies one raw compact boundary anchor against one exact historical public key."
  defdelegate verify_historical_anchor(compact, key, expected_anchor), to: Runtime

  @doc "Verifies one raw compact authenticated historical-key transition."
  defdelegate verify_key_transition(compact, current_key, next_key, expected), to: Runtime

  @doc "Atomically verifies one raw anchored export against caller boundaries and key history."
  defdelegate verify_anchored_export(archived, key_chain, expected), to: Runtime

  @doc "Verifies a raw grant-and-proof envelope against server-derived expected context."
  defdelegate check_envelope(credentials, expected_request), to: Runtime

  @doc "Returns the canonical type-preserving request digest."
  def request_digest(operation, cast_arguments, limits),
    do: RequestDigest.digest(operation, cast_arguments, limits)

  defp closed_header([], <<"EdDSA">>, <<"ba+cap">>, kid) when is_binary(kid), do: {:ok, kid}

  defp closed_header([{<<"alg">>, {:string, value}} | rest], nil, typ, kid),
    do: closed_header(rest, value, typ, kid)

  defp closed_header([{<<"typ">>, {:string, value}} | rest], alg, nil, kid),
    do: closed_header(rest, alg, value, kid)

  defp closed_header([{<<"kid">>, {:string, value}} | rest], alg, typ, nil),
    do: closed_header(rest, alg, typ, value)

  defp closed_header(_members, _alg, _typ, _kid), do: {:error, :invalid}

  defp valid_kid?(kid, maximum) when byte_size(kid) > 0 and byte_size(kid) <= maximum,
    do: kid_bytes?(kid)

  defp valid_kid?(_kid, _maximum), do: false

  defp kid_bytes?(<<>>), do: true

  defp kid_bytes?(<<byte, rest::binary>>)
       when byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?-, ?., ?_, ?~],
       do: kid_bytes?(rest)

  defp kid_bytes?(_kid), do: false
end
