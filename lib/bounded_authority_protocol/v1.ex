defmodule BoundedAuthorityProtocol.V1 do
  @moduledoc """
  Explicit entry point for the immutable v1 wire profile (contract-major 1, suite
  `BAP1-Ed25519-SHA256`, normative in `spec/bap-v1.md`).

  The functions fall into three groups:

    * **Producers** build the exact bytes a signer signs and assemble the compact form from a
      signature the caller made elsewhere: `grant_signing_input/2`, `proof_signing_input/2`,
      `boundary_anchor_signing_input/2`, `key_transition_signing_input/2`,
      `assemble_compact/2` and `assemble_compact/3`, `encode_consumption_entry/2`,
      `encode_anchored_export/2`, and `request_digest/3`. None of them takes a private key.
    * **Decoders** read a compact value without checking any signature, for diagnosis only:
      `decode_grant/2`, `decode_proof/2`, and `untrusted_key_locator/2`.
    * **Verifiers** check raw bytes against caller-supplied trusted public keys, expected
      context, time, and limits: `verify_grant/3`, `check_envelope/2`, `check_chain/2`,
      `verify_historical_anchor/3`, `verify_key_transition/4`, and `verify_anchored_export/3`.

  ## Return values

  Every function returns `{:ok, value}` or exactly `{:error, :invalid}`. The error carries no
  reason, on purpose: a wrong key, a changed byte, an expired window, a mismatched expectation,
  and an over-limit input all look the same. Functions never raise on bad input.

  Verified results are facts structs (`GrantFacts`, `EnvelopeFacts`, `ChainFacts`,
  `AnchorFacts`, `KeyTransitionFacts`, `AnchoredExportFacts`). They hold identifiers, digests,
  and times, never raw signatures, keys, nonces, or arguments, and they render as
  `#Module<redacted>`. `GrantFacts`, `EnvelopeFacts`, and `AnchoredExportFacts` carry
  `authorization: :not_evaluated`; `ChainFacts`, `AnchorFacts`, `KeyTransitionFacts`, and
  `AnchoredExportFacts` carry `trust: :not_evaluated`. A facts value is
  never an authorization decision.

  ## Limits

  `limits` is a map of tightening overrides (or a `BoundedAuthorityProtocol.V1.Bounds`
  struct); `%{}` means the profile maxima. See `BoundedAuthorityProtocol.V1.Bounds.coerce/1`.

  ## Example

  The getting-started guide and the README quickstart build a grant and a proof with these
  producers and verify them with `check_envelope/2`; the repository's test suite runs both.
  """

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

  @doc """
  Builds the deterministic grant signing input from a `BoundedAuthorityProtocol.V1.Grant`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.SigningInput{}}`; sign its `message` with the
  issuer key, then call `assemble_compact/2`. Returns `{:error, :invalid}` when a field is out
  of profile (for example an empty audience list, an expiry not after the start, or a selector
  outside the closed set) or over `limits`.
  """
  defdelegate grant_signing_input(grant, limits), to: Runtime

  @doc """
  Builds the deterministic holder-proof signing input from a `BoundedAuthorityProtocol.V1.Proof`.

  The input binds the grant (by the digest of its exact compact bytes), the method, the
  normalized target URI, the invocation id, the operation, the request digest of the typed
  `cast_arguments`, the issue time, and the optional nonce. Returns
  `{:ok, %BoundedAuthorityProtocol.V1.SigningInput{}}` or `{:error, :invalid}`; the holder
  public key must pass `BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1`.
  """
  defdelegate proof_signing_input(proof, limits), to: Runtime

  @doc """
  Encodes one consumption-chain row from a `BoundedAuthorityProtocol.V1.ConsumptionEntry`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.EncodedConsumptionEntry{bytes: row, hash: hash}}`
  with the exact canonical row bytes and their domain-separated hash, or `{:error, :invalid}`.
  """
  defdelegate encode_consumption_entry(entry, limits), to: Runtime

  @doc """
  Checks a nonempty range of raw consumption-chain rows (`BoundedAuthorityProtocol.V1.ChainInput`)
  against the caller's predecessor, head, and chain identity
  (`BoundedAuthorityProtocol.V1.ExpectedChain`).

  Returns `{:ok, %BoundedAuthorityProtocol.V1.ChainFacts{}}` or `{:error, :invalid}`. A
  consistent chain proves consistency only; it cannot show that a validly shortened history
  omitted nothing (usage rule 11).
  """
  defdelegate check_chain(input, expected), to: Runtime

  @doc """
  Builds the deterministic boundary-anchor signing input from a
  `BoundedAuthorityProtocol.V1.BoundaryAnchor`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.SigningInput{}}` or `{:error, :invalid}`.
  """
  defdelegate boundary_anchor_signing_input(anchor, limits), to: Runtime

  @doc """
  Builds the deterministic historical-key-transition signing input from a
  `BoundedAuthorityProtocol.V1.KeyTransition`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.SigningInput{}}` or `{:error, :invalid}`; both
  keys must pass `BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1`.
  """
  defdelegate key_transition_signing_input(transition, limits), to: Runtime

  @doc """
  Frames an anchored export from a `BoundedAuthorityProtocol.V1.AnchoredExportInput` after
  checking it against the caller's `BoundedAuthorityProtocol.V1.ExpectedExport`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.EncodedAnchoredExport{chunks: chunks, digest: digest,
  byte_count: count}}` or `{:error, :invalid}`.

  Since 0.9.0 (unreleased, planned for 0.9.0), encoding also refuses, with `{:error, :invalid}`, a
  signature that no conforming signer emits: an Ed25519 signature whose `S` is not below the group
  order or whose `R` is non-canonical or of small order (erratum 3). It never rewrites the
  signature bytes it accepts.
  """
  defdelegate encode_anchored_export(input, expected), to: Runtime

  @doc """
  Assembles the compact JWS from a signing input and a raw 64-byte Ed25519 signature, at the
  profile maxima. Same as `assemble_compact/3` with `%{}` limits.
  """
  @spec assemble_compact(SigningInput.t(), binary()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature),
    do: assemble_compact(signing_input, signature, %{})

  @doc """
  Assembles the compact JWS from a `BoundedAuthorityProtocol.V1.SigningInput` and a raw
  64-byte Ed25519 signature under caller `limits`.

  The assembled value is re-parsed as its kind (grant, proof, boundary anchor, or key
  transition) before it is returned as `{:ok, compact}`. The signature is not verified here:
  verification happens in `verify_grant/3`, `check_envelope/2`, and the evidence verifiers.
  Returns `{:error, :invalid}` for a wrong signature width, a signing input that does not
  re-parse, or an over-limit result.

  Since 0.9.0 (unreleased, planned for 0.9.0), assembly also refuses, with `{:error, :invalid}`, a
  signature that no conforming signer emits: an Ed25519 signature whose `S` is not below the group
  order or whose `R` is non-canonical or of small order (erratum 3). It never rewrites the
  signature bytes it accepts.
  """
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature, limits),
    do: Runtime.assemble_compact(signing_input, signature, limits)

  @doc """
  Decodes a raw compact grant within `limits` without checking its signature.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.DecodedGrant{verification: :not_evaluated}}` or
  `{:error, :invalid}`. Use it to diagnose a rejection, never to make a decision.
  """
  defdelegate decode_grant(compact, limits), to: Runtime

  @doc """
  Decodes a raw compact holder proof within `limits` without checking its signature.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.DecodedProof{verification: :not_evaluated}}` or
  `{:error, :invalid}`. Use it to diagnose a rejection, never to make a decision.
  """
  defdelegate decode_proof(compact, limits), to: Runtime

  @doc """
  Verifies one raw compact grant.

  `trusted_issuer` is a `BoundedAuthorityProtocol.V1.TrustedIssuer` with the exact `kid` and
  the raw 32-byte public key your service already trusts. `expected_grant` is a
  `BoundedAuthorityProtocol.V1.ExpectedGrant` with the issuer, the audience, the evaluation
  time, the clock skew (at most 60 seconds), and the limits.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.GrantFacts{authorization: :not_evaluated}}` or
  `{:error, :invalid}`.
  """
  defdelegate verify_grant(compact, trusted_issuer, expected_grant), to: Runtime

  @doc """
  Verifies one raw compact boundary anchor against one exact
  `BoundedAuthorityProtocol.V1.HistoricalPublicKey` and the caller's
  `BoundedAuthorityProtocol.V1.ExpectedAnchor`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.AnchorFacts{trust: :not_evaluated}}` or
  `{:error, :invalid}`.
  """
  defdelegate verify_historical_anchor(compact, key, expected_anchor), to: Runtime

  @doc """
  Verifies one raw compact historical-key transition, signed by `current_key`, that
  authenticates `next_key` (both `BoundedAuthorityProtocol.V1.HistoricalPublicKey`), against
  the caller's `BoundedAuthorityProtocol.V1.ExpectedKeyTransition`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.KeyTransitionFacts{trust: :not_evaluated}}` or
  `{:error, :invalid}`.
  """
  defdelegate verify_key_transition(compact, current_key, next_key, expected), to: Runtime

  @doc """
  Verifies one anchored export as a whole: the `BoundedAuthorityProtocol.V1.ArchivedObject`
  bytes and object version, its chunks to exact end of file, its digest, its boundary anchors,
  and the complete ordered `BoundedAuthorityProtocol.V1.HistoricalKeyChain`, against the
  caller's `BoundedAuthorityProtocol.V1.ExpectedAnchoredExport`.

  Returns `{:ok, %BoundedAuthorityProtocol.V1.AnchoredExportFacts{authorization: :not_evaluated}}`
  or `{:error, :invalid}`. Supply the expectations from your own records, never from the
  archive being verified (usage rule 10).
  """
  defdelegate verify_anchored_export(archived, key_chain, expected), to: Runtime

  @doc """
  Verifies a raw grant and holder proof together.

  `credentials` is a `BoundedAuthorityProtocol.V1.Credentials` with the exact grant and proof
  compact values as received. `expected_request` is a `BoundedAuthorityProtocol.V1.ExpectedRequest`
  with the trusted issuer, the expected issuer and audience, and the values your service
  derived from the request: method, normalized target URI, invocation id, operation, typed
  cast arguments, evaluation time, clock skew, proof maximum age (at most 300 seconds), and the
  nonce mode (`:not_required` or `{:required, nonce}`).

  The grant is re-verified, the proof signature is checked under the holder key the grant
  names, every binding is compared, and the arguments must satisfy every selector of the
  operation. Returns `{:ok, %BoundedAuthorityProtocol.V1.EnvelopeFacts{authorization: :not_evaluated}}`
  or `{:error, :invalid}`. Replay reservation of the invocation id stays with the caller.
  """
  defdelegate check_envelope(credentials, expected_request), to: Runtime

  @doc """
  Returns `{:ok, digest}`, the base64url SHA-256 request digest over the operation and the
  typed `cast_arguments` (`BAP1-REQUEST` domain), or `{:error, :invalid}`.

  Integer and float arguments stay distinct: `{:integer, 1}` and `{:float, 1.0}` digest
  differently.
  """
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
