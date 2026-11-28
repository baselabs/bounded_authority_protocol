defmodule BoundedAuthorityProtocol.Conformance.ProfileRunner do
  @moduledoc false

  alias BoundedAuthorityProtocol.ActionApproval.V1, as: Approval
  alias BoundedAuthorityProtocol.ActionApproval.V1.Record
  alias BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1, as: Loopback
  alias BoundedAuthorityProtocol.Conformance.Report
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1, as: ES256
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertion, as: EsAssertion
  alias BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts, as: EsFacts
  alias BoundedAuthorityProtocol.ContentAssertion.V1, as: EdDSA
  alias BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts
  alias BoundedAuthorityProtocol.HolderCustodyAttestation.V1, as: Custody
  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestation
  alias BoundedAuthorityProtocol.V1, as: V1Facade
  alias BoundedAuthorityProtocol.V1.{Bounds, HistoricalPublicKey, Jcs}
  alias BoundedAuthorityProtocol.V2, as: V2Facade
  alias BoundedAuthorityProtocol.V3, as: V3Facade

  @approval "bap-action-approval/1"
  @custody "bap-holder-custody-attestation/1"
  @es256 "bap-content-assertion-es256/1"

  @binary_fields ~w(attestor_key_fingerprint content_digest digest prev profile_digest
    public_key revision_digest subject_key_fingerprint)a
  @binary_field_keys Map.new(@binary_fields, &{&1, true})

  # Include the intentionally unsupported fixture key so the bounds validator rejects it.
  @fields Map.new(
            Map.keys(Bounds.__struct__()) ++
              ~w(action approver_role as_of assertion attestor attestor_key_id aud audience
                 bounds custody_class entries exp gen iat id iss issuer jti key key_id max_active
                 max_lifetime max_staleness nbf now profile provenance record record_bounds record_bytes
                 request_id resource_count resources roles snapshot sub subject suite trust
                 trust_domain unknown valid_before valid_from verification
                 version)a ++ @binary_fields,
            fn field -> {Atom.to_string(field), field} end
          )

  @index_keys ~w(elixir_verdict_sha256 files private_material_tracked profile revision verdict_sha256)

  def load(index, files) do
    with %{
           "files" => entries,
           "profile" => profile,
           "revision" => 1,
           "private_material_tracked" => false
         } <- index,
         true <-
           map_size(index) == length(@index_keys) and
             Enum.all?(@index_keys, &is_map_key(index, &1)),
         true <- is_list(entries) and map_size(files) == length(entries) + 1,
         true <- Enum.all?(entries, &file_matches?(&1, files)),
         {:ok, %{"profile" => ^profile, "revision" => 1} = metadata} <-
           decode_file(files, "profile.json"),
         {:ok, cases} <- checked_cases(entries, files) do
      {:ok, cases, metadata}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp checked_cases(entries, files) do
    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      case entry_cases(entry, files) do
        {:ok, cases} -> {:cont, {:ok, cases ++ acc}}
        {:error, :invalid} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, cases} -> {:ok, Enum.reverse(cases)}
      error -> error
    end
  end

  defp entry_cases(%{"path" => path, "cases" => count} = entry, files)
       when map_size(entry) == 3 and is_integer(count) and count > 0 do
    with {:ok, cases} when is_list(cases) and length(cases) == count <- decode_file(files, path),
         true <- Enum.all?(cases, &case_shape?/1) do
      {:ok, [{path, cases}]}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp entry_cases(%{"path" => "profile.json"} = entry, _files) when map_size(entry) == 2,
    do: {:ok, []}

  defp entry_cases(_entry, _files), do: {:error, :invalid}

  defp case_shape?(%{"id" => id, "expected" => _}) when is_binary(id), do: true
  defp case_shape?(_item), do: false

  # The CLI caps fixture files at 1 MiB. Their JSON arrays may contain multiple wire
  # objects and deliberately over-limit values, so wire bounds are applied by the verifier.
  defp decode_file(files, path) do
    case Map.fetch(files, path) do
      {:ok, bytes} -> {:ok, :json.decode(bytes)}
      :error -> {:error, :invalid}
    end
  catch
    :error, _reason -> {:error, :invalid}
  end

  defp file_matches?(%{"path" => path, "sha256" => hash}, files) do
    case Map.fetch(files, path) do
      {:ok, bytes} when is_binary(bytes) -> sha(bytes) == hash
      _missing -> false
    end
  end

  defp file_matches?(_entry, _files), do: false

  def run(corpus) do
    if known_answer?(Map.fetch!(corpus.index, "profile"), corpus.profile) do
      report(corpus.index_bytes, corpus.index, corpus.cases, corpus.profile)
    else
      {:error, :integrity}
    end
  end

  defp known_answer?(@approval, metadata) do
    %{"profile_preimage_hex" => hex, "profile_digest_hex" => digest} = metadata

    sha(Base.decode16!(hex, case: :lower)) == digest and
      Base.encode16(Approval.profile_digest(), case: :lower) == digest
  end

  defp known_answer?(@es256, %{"signing" => signing}) do
    with {:ok, input} <- signing_input(signing),
         true <- output(input) == Map.get(signing, "expected"),
         {:ok, compact} <- ES256.assemble_compact(input, raw(Map.get(signing, "signature"))) do
      compact == Map.get(signing, "compact")
    else
      _failure -> false
    end
  end

  defp known_answer?(@custody, %{
         "profile" => @custody,
         "revision" => 1,
         "attestor" => %{"key_id" => key_id},
         "signing" => %{"payload" => payload, "compact" => compact, "signature" => signature}
       }) do
    values = payload |> Map.delete("v") |> Map.put("attestor_key_id", key_id) |> fields()
    producer = struct!(Custody.HolderCustodyAttestation, values)

    case Custody.attestation_signing_input(producer, %{}) do
      {:ok, input} -> Custody.assemble_compact(input, raw(signature)) == {:ok, compact}
      {:error, :invalid} -> false
    end
  end

  defp known_answer?(_profile, _metadata), do: false

  defp report(index_bytes, index, cases, metadata) do
    {sdk, elixir} = partition_cases(cases)
    pure_cases = Map.new(elixir, fn {_path, item} -> {Map.get(item, "id"), item} end)

    results =
      Enum.map(elixir, fn {path, item} ->
        actual = execute(path, item, metadata, pure_cases)
        {[path <> "/" <> Map.get(item, "id"), actual], actual === Map.get(item, "expected")}
      end)

    rows = Enum.map(results, &elem(&1, 0))
    ids = Enum.map(rows, &hd/1)
    digest = verdict_digest(rows)
    total = length(elixir)
    agreed = Enum.count(results, &elem(&1, 1))

    agreement =
      total > 0 and length(ids) == total and length(Enum.uniq(ids)) == total and
        agreed == total and digest == Map.get(index, "elixir_verdict_sha256")

    status = if agreement, do: 0, else: 1

    report = %{
      "format" => "bounded-authority-protocol-candidate-conformance-report",
      "profile" => Map.get(index, "profile"),
      "agreement" => agreement,
      "exit_status" => status,
      "total" => total,
      "agreed" => agreed,
      "disagreed" => total - agreed,
      "sdk_owned" => length(sdk),
      "index_sha256_base64url" => Report.index_identity(index_bytes),
      "elixir_verdict_sha256" => digest
    }

    {:ok, :erlang.iolist_to_binary(canonical(report)), status}
  end

  def partition_cases(cases) do
    cases
    |> Enum.flat_map(fn {path, items} -> Enum.map(items, &{path, &1}) end)
    |> Enum.split_with(&sdk_case?/1)
  end

  def verdict_digest(rows), do: sha(canonical(rows))

  defp sdk_case?({"helper-cases.json", _item}), do: true
  defp sdk_case?({_path, %{"owner" => "sdk_helper"}}), do: true
  defp sdk_case?(_case), do: false

  defp execute("record-cases.json", item, _, _) do
    ca = fields(Map.get(item, "ca_bounds"))
    limits = fields(Map.get(item, "bounds"))

    encoded =
      case item do
        %{"wire" => wire} ->
          with {:ok, %Record{} = record} <- Approval.decode_record(raw(wire), ca, limits) do
            Approval.encode_record(record, ca, limits)
          end

        %{"author" => author} ->
          record = struct!(Record, fields(Map.delete(author, "v")))

          Approval.encode_record(record, ca, limits, Map.get(item, "canonicalize"))
      end

    case encoded do
      {:ok, wire} ->
        {:ok, digest} = EdDSA.content_digest(wire, ca)
        %{"wire" => b64(wire), "content_digest" => b64(digest)}

      {:error, :invalid} ->
        "invalid"
    end
  end

  defp execute(path, item, _, _) when path in ["approval-cases.json", "multi-fault-cases.json"] do
    case approval(item) do
      {:ok, facts} ->
        %{"record" => record} = result = output(facts)
        Map.put(result, "record", Map.put(record, "v", 1))

      {:error, code} ->
        Atom.to_string(code)
    end
  end

  defp execute("rendering-cases.json", item, _, pure_cases) do
    result = approval(Map.fetch!(pure_cases, Map.get(item, "pure_case")))

    render =
      case {Map.get(item, "id"), result} do
        {"nested-record", {:ok, %{record: record}}} -> record
        {"nested-assertion", {:ok, %{assertion: assertion}}} -> assertion
        _other -> result
      end

    Kernel.inspect(render)
  end

  defp execute("assertion-structure-cases.json", item, _, _) do
    compact = Map.get(item, "compact")
    bounds = fields(Map.get(item, "bounds"))

    with {:ok, artifact} <- ES256.decode_assertion(compact, bounds),
         {:ok, digest} <- ES256.assertion_digest(compact, bounds) do
      artifact
      |> output()
      |> Map.drop(["version", "verification"])
      |> Map.put("v", 1)
      |> Map.put("digest", b64(digest))
    else
      {:error, :invalid} -> "invalid"
    end
  end

  defp execute("assertion-verification-cases.json", item, _, _) do
    context = Map.get(item, "context") |> fields() |> Map.put(:bounds, %{})
    expected = struct!(ES256.ExpectedContentAssertion, context)

    case ES256.verify_assertion(Map.get(item, "compact"), expected) do
      {:ok, facts} -> output(facts)
      {:error, :invalid} -> "invalid"
    end
  end

  defp execute("digest-cases.json", item, _, _) do
    case ES256.content_digest(raw(Map.get(item, "input")), fields(Map.get(item, "bounds"))) do
      {:ok, digest} -> b64(digest)
      {:error, :invalid} -> "invalid"
    end
  end

  defp execute("assembly-cases.json", item, %{"signing" => signing}, _) do
    {:ok, input} = signing_input(signing)

    case ES256.assemble_compact(input, raw(Map.get(item, "signature"))) do
      {:ok, compact} -> compact
      {:error, :invalid} -> "invalid"
    end
  end

  defp execute("successor-cases.json", item, _, _) do
    previous = assertion_facts(Map.get(item, "previous_suite"), Map.get(item, "predecessor"))
    next = assertion_facts(Map.get(item, "next_suite"), Map.get(item, "successor"))

    case ES256.verify_successor(previous, next, %{}) do
      :ok -> "ok"
      {:error, :invalid} -> "invalid"
    end
  end

  defp execute("separation-cases.json", %{"id" => id, "foreign" => compact} = item, _, _) do
    with {:error, :invalid} <- ES256.decode_assertion(compact, %{}),
         {:ok, _} <- foreign(id, compact),
         {:error, :invalid} <- foreign(id, Map.get(item, "candidate")) do
      "both_reject"
    else
      _disagreement -> "unexpected"
    end
  end

  defp execute("attestation-cases.json", item, metadata, _) do
    subject = Map.get(item, "subject", Map.fetch!(metadata, "subject"))
    attestor = Map.get(item, "attestor", Map.fetch!(metadata, "attestor"))
    bounds = fields(Map.get(item, "bounds", %{}))
    compact = Map.fetch!(item, "compact")

    expected = %Custody.ExpectedAttestation{
      attestor: struct!(HistoricalPublicKey, fields(attestor)),
      subject_key_id: Map.fetch!(subject, "key_id"),
      subject_public_key: raw(Map.fetch!(subject, "public_key")),
      now: Map.get(item, "now", Map.fetch!(metadata, "now")),
      bounds: bounds
    }

    %{
      "decode" => attestation_outcome(Custody.decode_attestation(compact, bounds)),
      "verify" => attestation_outcome(Custody.verify_attestation(compact, expected))
    }
  end

  defp execute("custody-separation-cases.json", %{"id" => id} = item, _, _) do
    compact = Map.fetch!(item, "candidate")
    other = Map.fetch!(item, "foreign")
    other = if id == "action-approval-record", do: raw(other), else: other

    if match?({:ok, _}, Custody.decode_attestation(compact, %{})) and
         match?({:ok, _}, foreign(id, other)) and
         Custody.decode_attestation(other, %{}) == {:error, :invalid} and
         foreign(id, compact) == {:error, :invalid} do
      "both_reject"
    else
      "unexpected"
    end
  end

  defp attestation_outcome({:ok, value}), do: output(value)
  defp attestation_outcome({:error, :invalid}), do: "invalid"

  defp approval(item) do
    record = raw(Map.get(item, "record"))
    compact = Map.get(item, "compact")
    context = fields(Map.get(item, "context"))

    case Map.get(item, "suite") do
      "eddsa" -> Approval.verify_eddsa(record, compact, context)
      "es256" -> Approval.verify_es256(record, compact, context)
    end
  end

  defp assertion_facts("eddsa", values), do: struct!(ContentAssertionFacts, fields(values))
  defp assertion_facts("es256", values), do: struct!(EsFacts, fields(values))

  defp signing_input(signing) do
    %{"payload" => payload, "kid" => key_id} = signing

    values =
      payload
      |> Map.delete("v")
      |> Map.put("attestor_key_id", key_id)
      |> fields()

    producer = struct!(EsAssertion, values)
    ES256.assertion_signing_input(producer, %{})
  end

  defp fields(value) when is_list(value), do: Enum.map(value, &fields/1)
  defp fields(:null), do: nil

  defp fields(value) when is_map(value) do
    Map.new(value, fn {key, value} ->
      field = Map.fetch!(@fields, key)
      {field, field_value(field, value)}
    end)
  end

  defp fields(value), do: value

  defp field_value(field, value) when is_map_key(@binary_field_keys, field), do: raw(value)

  # Preserve exact fixture keys so malformed historical entries reach snapshot admission.
  defp field_value(field, value) when field in [:attestor, :key] and is_map(value),
    do: Map.put(fields(value), :__struct__, HistoricalPublicKey)

  defp field_value(:suite, "eddsa"), do: :eddsa
  defp field_value(:suite, "es256"), do: :es256
  defp field_value(:trust, "not_evaluated"), do: :not_evaluated
  defp field_value(:verification, "signature_and_window"), do: :signature_and_window
  defp field_value(:valid_before, "unbounded"), do: :unbounded
  defp field_value(_, value), do: fields(value)

  defp output(%{__struct__: _} = value), do: value |> Map.from_struct() |> output()

  defp output(value) when is_map(value) do
    Map.new(value, fn {key, value} ->
      rendered = if is_map_key(@binary_field_keys, key), do: b64(value), else: output(value)
      {Atom.to_string(key), rendered}
    end)
  end

  defp output(value) when is_atom(value), do: Atom.to_string(value)
  defp output(value), do: value

  # A corpus verdict stream may exceed wire bounds. Frame its rows as JCS and encode
  # scalar strings separately. Large strings in these pinned projections are base64url.
  defp canonical(value) when is_list(value),
    do: ["[", Enum.intersperse(Enum.map(value, &canonical/1), ","), "]"]

  defp canonical(value) when is_map(value) do
    members =
      value
      |> Enum.sort()
      |> Enum.map(fn {key, item} -> [canonical(key), ":", canonical(item)] end)

    ["{", Enum.intersperse(members, ","), "}"]
  end

  defp canonical(value) when is_binary(value) and byte_size(value) > 8_192,
    do: [?", value, ?"]

  defp canonical(value) when is_binary(value) do
    {:ok, bytes} = Jcs.encode({:string, value}, %{})
    bytes
  end

  defp canonical(value) when is_integer(value), do: Integer.to_string(value)
  defp canonical(true), do: "true"
  defp canonical(false), do: "false"

  defp raw(value), do: Base.url_decode64!(value, padding: false)
  defp b64(bytes), do: Base.url_encode64(bytes, padding: false)
  defp sha(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp foreign("ca1", compact),
    do: EdDSA.decode_assertion(compact, %{})

  defp foreign("ca-es256", compact),
    do: ES256.decode_assertion(compact, %{})

  defp foreign("action-approval-record", bytes),
    do: Approval.decode_record(bytes, %{}, %{})

  defp foreign("loopback", compact),
    do: Loopback.decode_proof(compact, %{})

  defp foreign("role-attestation", compact),
    do: RoleAttestation.decode_attestation(compact, %{})

  defp foreign("v1-grant", compact),
    do: V1Facade.decode_grant(compact, %{})

  defp foreign("v1-proof", compact),
    do: V1Facade.decode_proof(compact, %{})

  defp foreign("v1-anchor", compact),
    do: V1Facade.BoundaryAnchorCodec.parse(compact, Bounds.maximum())

  defp foreign("v1-transition", compact),
    do: V1Facade.KeyTransitionCodec.parse(compact, Bounds.maximum())

  defp foreign("v2-grant", compact),
    do: V2Facade.decode_grant(compact, %{})

  defp foreign("v2-proof", compact),
    do: V2Facade.decode_proof(compact, %{})

  defp foreign("v2-anchor", compact),
    do: V2Facade.BoundaryAnchorCodec.parse(compact, Bounds.maximum())

  defp foreign("v2-transition", compact),
    do: V2Facade.KeyTransitionCodec.parse(compact, Bounds.maximum())

  defp foreign("v3-grant", compact),
    do: V3Facade.decode_grant(compact, %{})

  defp foreign("v3-proof", compact),
    do: V3Facade.decode_proof(compact, %{})

  defp foreign("v3-anchor", compact),
    do: V3Facade.BoundaryAnchorCodec.parse(compact, Bounds.maximum())

  defp foreign("v3-transition", compact),
    do: V3Facade.KeyTransitionCodec.parse(compact, Bounds.maximum())
end
