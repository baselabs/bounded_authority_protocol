defmodule BoundedAuthorityProtocol.ActionApproval.V1 do
  @moduledoc """
  Canonical action approval records and caller-context verification.

  Select the configured suite with `verify_eddsa/3` or `verify_es256/3` before
  processing the presented bytes. The returned diagnostics are for local use.
  Presenter-facing failures use the single `invalid` result.
  """

  alias BoundedAuthorityProtocol.ActionApproval.V1.{Record, RecordCodec, VerifiedApprovalFacts}
  alias BoundedAuthorityProtocol.ContentAssertion.V1.Codec
  alias BoundedAuthorityProtocol.V1.{Bounds, FixedBytes, HistoricalPublicKey}

  @profile "bap-action-approval/1"
  # SHA-256 of the domain, separator and immutable descriptor bytes. The corpus
  # checks the complete preimage and the resulting constant.
  @profile_digest <<0x7e44f73217cd25037839ecc25837de84aad3673626b9b125c94c97e9967fa1eb::256>>

  @typedoc "The positive, independently tightenable record ceilings."
  @type record_bounds :: %{
          optional(:string_bytes) => pos_integer(),
          optional(:resource_count) => pos_integer(),
          optional(:record_bytes) => pos_integer()
        }

  @typedoc "The caller-enrolled issuer, key and current unique approver roles."
  @type entry :: %{
          issuer: binary(),
          key: HistoricalPublicKey.t(),
          roles: [binary()]
        }

  @typedoc "A caller-supplied key snapshot with independently established provenance."
  @type snapshot :: %{
          trust_domain: binary(),
          suite: :eddsa | :es256,
          provenance: binary(),
          as_of: integer(),
          entries: [entry()]
        }

  @typedoc "Independent expected operation, trusted time, policy and snapshot."
  @type context :: %{
          optional(:max_active) => non_neg_integer(),
          optional(:snapshot) => snapshot() | nil,
          trust_domain: binary(),
          audience: binary(),
          request_id: binary(),
          revision_digest: binary(),
          subject: binary(),
          action: binary(),
          resources: [binary()],
          roles: [binary()],
          now: integer(),
          max_staleness: non_neg_integer(),
          max_lifetime: non_neg_integer(),
          bounds: Bounds.t() | map(),
          record_bounds: record_bounds()
        }

  @typedoc "Value-free diagnostic for the first failed verification stage."
  @type diagnostic ::
          :invalid_context
          | :trust_unavailable
          | :stale_trust
          | :malformed
          | :unsupported_algorithm
          | :unknown_key
          | :bad_signature
          | :key_window
          | :record_mismatch
          | :issuer_mismatch
          | :audience_mismatch
          | :request_mismatch
          | :subject_mismatch
          | :scope_mismatch
          | :not_yet_valid
          | :expired
          | :lifetime_too_long
          | :active_too_long
          | :role_not_permitted

  @doc "Returns the raw 32-byte digest of the frozen profile descriptor preimage."
  @spec profile_digest() :: binary()
  def profile_digest, do: @profile_digest

  @doc "Encodes a record; pass `true` to sort and deduplicate validated resource names."
  @spec encode_record(Record.t(), Bounds.t() | map(), record_bounds(), boolean()) ::
          {:ok, binary()} | {:error, :invalid}
  def encode_record(record, limits \\ %{}, record_limits \\ %{}, canonicalize? \\ false) do
    with {:ok, ca} <- Bounds.coerce(limits),
         {:ok, bounds} <- RecordCodec.bounds(record_limits, ca) do
      RecordCodec.encode(record, bounds, ca, canonicalize?)
    end
  end

  @doc "Decodes exactly canonical wire bytes under the effective record bounds."
  @spec decode_record(binary(), Bounds.t() | map(), record_bounds()) ::
          {:ok, Record.t()} | {:error, :invalid}
  def decode_record(bytes, limits \\ %{}, record_limits \\ %{}) do
    with {:ok, ca} <- Bounds.coerce(limits),
         {:ok, bounds} <- RecordCodec.bounds(record_limits, ca) do
      RecordCodec.parse(bytes, bounds, ca)
    end
  end

  @doc "Verifies a record and a CA1 assertion against the supplied context."
  @spec verify_eddsa(binary(), binary(), context()) ::
          {:ok, VerifiedApprovalFacts.t()} | {:error, diagnostic()}
  def verify_eddsa(record, compact, context), do: verify(:eddsa, record, compact, context)

  @doc "Verifies a record and an ES256 content assertion against the supplied context."
  @spec verify_es256(binary(), binary(), context()) ::
          {:ok, VerifiedApprovalFacts.t()} | {:error, diagnostic()}
  def verify_es256(record, compact, context), do: verify(:es256, record, compact, context)

  defp verify(suite, bytes, compact, context) do
    with {:ok, ca, bounds, max_active} <- preflight(context),
         {:ok, keys, as_of} <-
           admit_snapshot(Map.get(context, :snapshot), context, suite, ca, bounds),
         :ok <- check(fresh?(context.now - as_of, context.max_staleness), :stale_trust),
         {:ok, parsed} <- Codec.parse(compact, ca, suite),
         {:ok, record} <- parse_record(bytes, bounds, ca),
         {:ok, entry} <- key_entry(keys, parsed.attestor_key_id),
         :ok <- Codec.signature(parsed, entry.key, suite),
         :ok <- Codec.key_window(parsed, entry.key),
         :ok <- record_binding(parsed, bytes, ca),
         :ok <- check(parsed.iss == entry.issuer, :issuer_mismatch),
         :ok <- check(parsed.aud == context.audience, :audience_mismatch),
         :ok <- request_binding(parsed, record, context),
         :ok <- check(record.subject == context.subject, :subject_mismatch),
         :ok <- check(record.action == context.action, :scope_mismatch),
         :ok <- check(record.resources == context.resources, :scope_mismatch),
         :ok <- Codec.current_window(parsed, context.now),
         :ok <- check(parsed.exp - parsed.iat <= context.max_lifetime, :lifetime_too_long),
         :ok <-
           check(is_nil(max_active) or parsed.exp - parsed.nbf <= max_active, :active_too_long),
         :ok <- check(Enum.member?(context.roles, record.approver_role), :role_not_permitted),
         :ok <- check(Enum.member?(entry.roles, record.approver_role), :role_not_permitted) do
      {:ok,
       %VerifiedApprovalFacts{
         suite: suite,
         trust_domain: context.trust_domain,
         record: record,
         assertion: Codec.facts(parsed, compact, entry.fingerprint, suite)
       }}
    end
  end

  defp fresh?(age, cap), do: age >= 0 and age <= cap

  defp scalar_identity?(value, bounds) do
    is_binary(value) and value != "" and byte_size(value) <= bounds.identifier_bytes and
      String.valid?(value)
  end

  defp preflight(%{
         trust_domain: domain,
         audience: audience,
         request_id: request,
         revision_digest: revision,
         subject: subject,
         action: action,
         resources: resources,
         roles: [_ | _] = roles,
         now: now,
         max_staleness: staleness,
         max_lifetime: lifetime,
         bounds: limits,
         record_bounds: record_limits
       } = context) do
    result =
      with {:ok, ca} <- Bounds.coerce(limits),
           {:ok, bounds} <- RecordCodec.bounds(record_limits, ca),
           true <- scalar_identity?(domain, ca) and Codec.identifier?(audience, ca),
           true <- RecordCodec.request_id?(request, bounds, ca),
           true <- is_binary(revision) and byte_size(revision) == 32,
           true <- RecordCodec.text?(subject, bounds) and RecordCodec.text?(action, bounds),
           true <- RecordCodec.resources?(resources, bounds, false),
           true <- valid_roles?(roles, bounds, MapSet.new()),
           true <- Codec.integer?(now, ca),
           true <- cap?(staleness, ca) and cap?(lifetime, ca),
           {:ok, active} <- active_cap(Map.fetch(context, :max_active), ca) do
        {:ok, ca, bounds, active}
      end

    stage(result, :invalid_context)
  end

  defp preflight(_), do: {:error, :invalid_context}

  defp active_cap(:error, _ca), do: {:ok, nil}

  defp active_cap({:ok, value}, ca) do
    if cap?(value, ca), do: {:ok, value}, else: {:error, :invalid_context}
  end

  defp cap?(value, ca), do: Codec.integer?(value, ca) and value >= 0

  defp admit_snapshot(
         %{
           trust_domain: domain,
           suite: suite,
           provenance: provenance,
           as_of: as_of,
           entries: entries
         },
         %{trust_domain: domain},
         suite,
         ca,
         bounds
       ) do
    result =
      with true <- scalar_identity?(provenance, ca) and Codec.integer?(as_of, ca),
           {:ok, keys} <- admit_entries(entries, %{}, suite, ca, bounds) do
        {:ok, keys, as_of}
      end

    stage(result, :trust_unavailable)
  end

  defp admit_snapshot(_, _, _, _, _), do: {:error, :trust_unavailable}

  defp admit_entries([], keys, _, _, _), do: {:ok, keys}

  defp admit_entries(
         [%{issuer: issuer, key: %HistoricalPublicKey{key_id: kid} = key, roles: roles} | rest],
         keys,
         suite,
         ca,
         bounds
       )
       when map_size(key) == 5 do
    result =
      with false <- Map.has_key?(keys, kid),
           true <- Codec.identifier?(issuer, ca) and valid_roles?(roles, bounds, MapSet.new()),
           :ok <- Codec.historical_key(key, ca, suite),
           {:ok, fingerprint} <- Codec.admitted_fingerprint(key.public_key, ca, suite) do
        entry = %{issuer: issuer, key: key, roles: roles, fingerprint: fingerprint}
        admit_entries(rest, Map.put(keys, kid, entry), suite, ca, bounds)
      end

    stage(result, :trust_unavailable)
  end

  defp admit_entries(_, _, _, _, _), do: {:error, :trust_unavailable}

  defp valid_roles?([], _, _), do: true

  defp valid_roles?([role | rest], bounds, seen),
    do:
      RecordCodec.text?(role, bounds) and not MapSet.member?(seen, role) and
        valid_roles?(rest, bounds, MapSet.put(seen, role))

  defp valid_roles?(_, _, _), do: false

  defp parse_record(bytes, bounds, ca) do
    case RecordCodec.parse(bytes, bounds, ca) do
      {:error, :invalid} -> {:error, :malformed}
      {:ok, record} -> {:ok, record}
    end
  end

  defp key_entry(keys, kid) do
    case Map.fetch(keys, kid) do
      :error -> {:error, :unknown_key}
      {:ok, entry} -> {:ok, entry}
    end
  end

  defp record_binding(parsed, bytes, ca) do
    {:ok, digest} = Codec.content_digest(bytes, ca)

    check(
      FixedBytes.equal?(parsed.content_digest, digest) and parsed.profile == @profile and
        FixedBytes.equal?(parsed.profile_digest, @profile_digest),
      :record_mismatch
    )
  end

  defp request_binding(parsed, record, context) do
    check(
      record.request_id == context.request_id and record.request_id == parsed.sub and
        FixedBytes.equal?(record.revision_digest, context.revision_digest),
      :request_mismatch
    )
  end

  defp check(true, _code), do: :ok
  defp check(false, code), do: {:error, code}

  defp stage({:ok, _} = result, _code), do: result
  defp stage({:ok, _, _} = result, _code), do: result
  defp stage({:ok, _, _, _} = result, _code), do: result
  defp stage(_, code), do: {:error, code}
end
