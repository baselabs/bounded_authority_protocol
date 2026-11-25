defmodule BoundedAuthorityProtocol.Conformance.Candidate do
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
  alias BoundedAuthorityProtocol.RoleAttestation.V1, as: RoleAttestation
  alias BoundedAuthorityProtocol.V1, as: V1Facade
  alias BoundedAuthorityProtocol.V1.{Bounds, HistoricalPublicKey, Jcs}
  alias BoundedAuthorityProtocol.V2, as: V2Facade
  alias BoundedAuthorityProtocol.V3, as: V3Facade

  @approval "bap-action-approval/1"
  @es256 "bap-content-assertion-es256/1"

  # Source candidate identities. The released corpus catalog remains independently gated.
  @pins %{
    "NUcBmDSfKwOwxd9DaFaaQ36uOYR_pLjfHNHySzPW-CY" => @approval,
    "15Mp1DHeCT8WJhP70qL-g4dmtpD6Z8-8FHjq-jIrPGM" => @es256
  }

  @binary_fields ~w(attestor_key_fingerprint content_digest digest prev profile_digest
    public_key revision_digest)a
  @binary_field_keys Map.new(@binary_fields, &{&1, true})

  # Include the intentionally unsupported fixture key so the bounds validator rejects it.
  @fields Map.new(
            Map.keys(Bounds.__struct__()) ++
              ~w(action approver_role as_of assertion attestor attestor_key_id aud audience
                 bounds entries exp gen iat id iss issuer jti key key_id max_active max_lifetime
                 max_staleness nbf now profile provenance record record_bounds record_bytes
                 request_id resource_count resources roles snapshot sub subject suite trust
                 trust_domain unknown valid_before valid_from verification
                 version)a ++ @binary_fields,
            fn field -> {Atom.to_string(field), field} end
          )

  def identify(index_bytes), do: Map.get(@pins, Report.index_identity(index_bytes))

  def run(files, profile) do
    index_bytes = Map.fetch!(files, "index.json")
    index = :json.decode(index_bytes)

    with %{"profile" => ^profile, "files" => entries} <- index,
         true <- map_size(files) == length(entries) + 1,
         {:ok, cases, metadata} <- checked_cases(entries, files),
         true <- known_answer?(profile, metadata) do
      report(index_bytes, index, cases, metadata)
    else
      _failure -> {:error, :integrity}
    end
  end

  # The pinned index fixes order, names and counts. Verify each file before decoding it.
  defp checked_cases(entries, files) do
    with true <-
           Enum.all?(entries, fn %{"path" => path, "sha256" => hash} ->
             case Map.fetch(files, path) do
               {:ok, bytes} -> sha(bytes) == hash
               :error -> false
             end
           end) do
      cases =
        Enum.flat_map(entries, fn
          %{"path" => path, "cases" => count} ->
            list = :json.decode(Map.fetch!(files, path))
            if length(list) == count, do: Enum.map(list, &{path, &1}), else: [:wrong_count]

          _metadata ->
            []
        end)

      if Enum.all?(cases, &match?({_path, _item}, &1)),
        do: {:ok, cases, :json.decode(Map.fetch!(files, "profile.json"))},
        else: {:error, :integrity}
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

  defp report(index_bytes, index, cases, metadata) do
    {sdk, elixir} = Enum.split_with(cases, &sdk_case?/1)
    pure_cases = Map.new(elixir, fn {_path, item} -> {Map.get(item, "id"), item} end)

    results =
      Enum.map(elixir, fn {path, item} ->
        actual = execute(path, item, metadata, pure_cases)
        {[path <> "/" <> Map.get(item, "id"), actual], actual === Map.get(item, "expected")}
      end)

    rows = Enum.map(results, &elem(&1, 0))
    ids = Enum.map(rows, &hd/1)
    digest = sha(canonical(rows))
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
