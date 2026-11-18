defmodule BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1 do
  @moduledoc """
  Byte-distinct holder proofs for literal-loopback HTTP development listeners.

  This profile reuses contract-major 1 grants, keys, request digests, and expected-request types,
  but has its own proof header and URI rules. It never retries the standard HTTPS profile.
  See the [normative specification](../spec/bap-local-loopback-http-v1.md).

  ## Required context

  `check_envelope/2` takes raw `BoundedAuthorityProtocol.V1.Credentials` and a complete
  `BoundedAuthorityProtocol.V1.ExpectedRequest`: already-trusted issuer key, expected issuer,
  audience, method, normalized target URI, invocation ID, operation, tagged cast arguments,
  evaluation time in integer Unix seconds, clock skew, proof maximum age, nonce, and bounds.
  Use `nonce: {:required, issued_nonce}`. `:not_required` is always refused by this profile.
  The host issues and atomically retires that nonce; pure verification only checks its match.

  Targets use HTTP with the literal host `127.0.0.1` or `[::1]` and an optional port from 1 to
  65535; port 80 is omitted in normal form. Names such as `localhost`, alternate IP spellings, userinfo, query, and fragment are
  refused. Normalization performs no DNS or network access. This is not a production transport
  security substitute. Configure expected context from trusted routing, not client host headers.

  ## Operations and results

  * `normalize_uri/2` returns `{:ok, normalized_uri}` under the closed loopback rules.
  * `proof_signing_input/2` returns `{:ok, SigningInput}` with the exact bytes to sign elsewhere.
  * `assemble_compact/2` and `assemble_compact/3` return `{:ok, compact}` after checking profile
    structure and signature encoding. Assembly establishes neither signature validity nor trust.
  * `decode_proof/2` returns `{:ok, DecodedProof}` for untrusted diagnosis without a signature check.
  * `check_envelope/2` re-verifies both raw credentials and returns `{:ok, EnvelopeFacts}` with
    redacted inspection and `authorization: :not_evaluated`.

  Every operation returns exactly `{:error, :invalid}` on invalid or over-limit input or a failed
  check. `%{}` limits use profile maxima and overrides only tighten them. Public keys and time
  are explicit inputs; this package has no private-key access or custody. The host still owns
  trust selection, invocation and nonce reservation, live revocation, and authorization policy.

  ## Executed example

  [The loopback recipe](../docs/guides/recipes.md#verify-a-local-loopback-request) signs a proof,
  verifies it with a required nonce, and rejects the same envelope in nonce-optional mode. The
  documentation consumer executes the actual example.
  """

  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.Uri
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.DecodedProof
  alias BoundedAuthorityProtocol.V1.EnvelopeFacts
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.Proof
  alias BoundedAuthorityProtocol.V1.Runtime
  alias BoundedAuthorityProtocol.V1.SigningInput

  @doc """
  Normalizes one bounded local-loopback HTTP target URI without DNS or network access.

  ## Examples

      iex> BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.normalize_uri("http://127.0.0.1:8080/items", %{})
      {:ok, "http://127.0.0.1:8080/items"}
      iex> BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.normalize_uri("http://localhost:8080/items", %{})
      {:error, :invalid}
  """
  @spec normalize_uri(binary(), Bounds.t() | map()) :: {:ok, binary()} | {:error, :invalid}
  defdelegate normalize_uri(uri, limits), to: Uri, as: :normalize

  @doc """
  Builds the deterministic byte-distinct local-loopback proof signing input.

  ## Examples

      iex> BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.proof_signing_input(%{}, %{})
      {:error, :invalid}
  """
  @spec proof_signing_input(Proof.t(), Bounds.t() | map()) ::
          {:ok, SigningInput.t()} | {:error, :invalid}
  defdelegate proof_signing_input(proof, limits),
    to: Runtime,
    as: :local_loopback_proof_signing_input

  @doc """
  Assembles a local-loopback proof at profile maxima.

  ## Examples

      iex> BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.assemble_compact(%{}, "")
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary()) :: {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature),
    do: assemble_compact(signing_input, signature, %{})

  @doc """
  Assembles a local-loopback proof under caller bounds.

  Since 0.9.0, assembly also refuses, with `{:error, :invalid}`, a
  signature that no conforming signer emits: an Ed25519 signature whose `S` is not below the group
  order or whose `R` is non-canonical or of small order (erratum 3). It never rewrites the
  signature bytes it accepts.

  ## Examples

      iex> BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.assemble_compact(%{}, "", %{})
      {:error, :invalid}
  """
  @spec assemble_compact(SigningInput.t(), binary(), Bounds.t() | map()) ::
          {:ok, binary()} | {:error, :invalid}
  def assemble_compact(signing_input, signature, limits),
    do: Runtime.assemble_local_loopback_compact(signing_input, signature, limits)

  @doc """
  Boundedly decodes a local-loopback proof without evaluating trust.

  ## Examples

      iex> BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.decode_proof("not.a.compact", %{})
      {:error, :invalid}
  """
  @spec decode_proof(binary(), Bounds.t() | map()) :: {:ok, DecodedProof.t()} | {:error, :invalid}
  defdelegate decode_proof(compact, limits), to: Runtime, as: :decode_local_loopback_proof

  @doc """
  Verifies a raw grant and local-loopback proof against server-derived context.

  ## Examples

      iex> BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1.check_envelope(%{}, %{})
      {:error, :invalid}
  """
  @spec check_envelope(Credentials.t(), ExpectedRequest.t()) ::
          {:ok, EnvelopeFacts.t()} | {:error, :invalid}
  defdelegate check_envelope(credentials, expected_request),
    to: Runtime,
    as: :check_local_loopback_envelope
end
