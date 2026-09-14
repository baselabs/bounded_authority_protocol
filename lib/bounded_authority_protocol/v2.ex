defmodule BoundedAuthorityProtocol.V2 do
  @moduledoc """
  Explicit entry point for the v2 wire profile (contract-major 2, the
  [`BAP2-Ed25519-SHA256`](../docs/design/registries.md) suite).

  The v2 profile is byte-distinct from v1: grant and proof payloads carry `v: 2`,
  domain separators are `BAP2-*`, and the selector algebra admits the two
  inclusive range kinds `lte`/`gte` ([ADR 0028](../docs/adr/0028-range-selector-kinds.md)).
  Each major verifies under its own complete closed profile; the v1 façade
  rejects v2 bytes and this façade rejects v1 bytes.
  """

  alias BoundedAuthorityProtocol.V1, as: V1Facade
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.KeyLocator
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V2.RequestDigest
  alias BoundedAuthorityProtocol.V2.Runtime

  @doc """
  Parses only the protected grant header and returns its untrusted `kid` hint.

  The complete compact input is bounded. Payload and signature segments are not decoded,
  interpreted, or independently size-checked. The header walk is major-neutral (it inspects
  `alg`/`typ`/`kid` only), so it delegates to the shared v1 implementation.
  """
  @spec untrusted_key_locator(binary(), Bounds.t() | map()) ::
          {:ok, KeyLocator.t()} | {:error, :invalid}
  def untrusted_key_locator(compact, limits \\ %{})

  def untrusted_key_locator(compact, limits),
    do: V1Facade.untrusted_key_locator(compact, limits)

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
end
