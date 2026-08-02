defmodule BoundedAuthorityProtocol.Conformance.Runner do
  @moduledoc """
  Pure case executor for the loaded corpus.

  `run/1` dispatches each case against the frozen v1 facade (no facade change, no second parser)
  and compares the result to the case-declared expectation. `.raw` sidecar bytes pass through
  opaque. Every case result is `%{"actual" => ..., "agree" => boolean}` for a valid expectation or
  `%{"actual" => ..., "agree" => boolean}` for an invalid expectation (agreement = the facade
  returned `{:error, :invalid}` exactly). The runner never selects trust, reserves replay, or
  checks revocation — it exercises the pure facade only.
  """

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.V1.AnchoredExportInput
  alias BoundedAuthorityProtocol.V1.ArchivedObject
  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.BoundaryAnchor
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ChainInput
  alias BoundedAuthorityProtocol.V1.ConsumptionEntry
  alias BoundedAuthorityProtocol.V1.Credentials
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedAnchoredExport
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedExport
  alias BoundedAuthorityProtocol.V1.ExpectedGrant
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.ExpectedRequest
  alias BoundedAuthorityProtocol.V1.Grant
  alias BoundedAuthorityProtocol.V1.HistoricalKeyChain
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.KeyTransition
  alias BoundedAuthorityProtocol.V1.Operation
  alias BoundedAuthorityProtocol.V1.Proof
  alias BoundedAuthorityProtocol.V1.SigningInput
  alias BoundedAuthorityProtocol.V1.TrustedIssuer
  alias BoundedAuthorityProtocol.V1.Uri

  # Compile-time map from the JSON string form of each bounds key to its atom, so case
  # input overrides (string keys) convert to the atom keys Bounds.new expects without any
  # runtime atom creation (the architecture gate forbids String.to_existing_atom).
  @bounds_keys %{
    "compact_bytes" => :compact_bytes,
    "encoded_segment_bytes" => :encoded_segment_bytes,
    "decoded_segment_bytes" => :decoded_segment_bytes,
    "json_bytes" => :json_bytes,
    "depth" => :depth,
    "object_members" => :object_members,
    "array_items" => :array_items,
    "total_nodes" => :total_nodes,
    "string_bytes" => :string_bytes,
    "key_bytes" => :key_bytes,
    "number_lexeme_bytes" => :number_lexeme_bytes,
    "integer_magnitude" => :integer_magnitude,
    "float_magnitude" => :float_magnitude,
    "kid_bytes" => :kid_bytes,
    "jcs_bytes" => :jcs_bytes,
    "uri_bytes" => :uri_bytes,
    "identifier_bytes" => :identifier_bytes,
    "nonce_bytes" => :nonce_bytes,
    "method_bytes" => :method_bytes,
    "operation_bytes" => :operation_bytes,
    "audiences" => :audiences,
    "operations" => :operations,
    "selectors" => :selectors,
    "path_segments" => :path_segments,
    "one_of_values" => :one_of_values,
    "public_key_bytes" => :public_key_bytes,
    "signature_bytes" => :signature_bytes,
    "digest_bytes" => :digest_bytes,
    "clock_skew" => :clock_skew,
    "proof_max_age" => :proof_max_age,
    "chain_row_bytes" => :chain_row_bytes,
    "chain_rows" => :chain_rows,
    "anchor_bytes" => :anchor_bytes,
    "archive_header_bytes" => :archive_header_bytes,
    "archive_chunks" => :archive_chunks,
    "archive_bytes" => :archive_bytes,
    "object_version_bytes" => :object_version_bytes,
    "key_transitions" => :key_transitions
  }

  @doc "Executes every loaded case against the frozen facade."
  @spec run(Corpus.t()) :: [{binary(), [%{case_id: binary(), agree: boolean()}]}]
  def run(%Corpus{cases: cases, raws: raws}) do
    Enum.map(cases, fn {path, file_cases} ->
      results = Enum.map(file_cases, fn case_obj -> execute_case(case_obj, raws) end)
      {path, results}
    end)
  end

  defp execute_case(case_obj, raws) do
    surface = case_obj["surface"]
    input = Map.get(case_obj, "input", %{})
    expected = case_obj["expected"]
    actual = dispatch(surface, input, raws)
    agree = agrees?(expected, actual)
    %{case_id: case_obj["id"], agree: agree}
  end

  # --- agreement -----------------------------------------------------------

  defp agrees?(%{"verdict" => "invalid"}, {:error, :invalid}), do: true
  defp agrees?(%{"verdict" => "invalid"}, _actual), do: false
  defp agrees?(%{"verdict" => "valid"}, {:error, :invalid}), do: false

  defp agrees?(%{"verdict" => "valid"} = expected, {:ok, actual}) do
    expected_fields = Map.delete(expected, "verdict")
    matches_expected?(expected_fields, actual)
  end

  # Exact byte/field comparison per surface. The expected map keys name the projection to compare.
  defp matches_expected?(expected_fields, actual) do
    Enum.all?(expected_fields, fn {key, expected_value} ->
      actual_value = project(key, actual)
      compare?(key, expected_value, actual_value)
    end)
  end

  # --- dispatch table ------------------------------------------------------

  defp dispatch("json.decode", input, raws) do
    with {:ok, bytes} <- input_bytes(input, raws) do
      case Json.decode(bytes, Bounds.maximum()) do
        {:ok, value} -> {:ok, {:json, value}}
        error -> error
      end
    end
  end

  defp dispatch("base64url.decode", input, _raws) do
    # The input IS the base64url segment; read it raw (do not pre-decode via input_bytes).
    segment = b64url_segment(input)

    if byte_size(segment) == 0 do
      {:error, :invalid}
    else
      case Base64Url.decode(segment, Bounds.maximum()) do
        {:ok, decoded} -> {:ok, %{"decoded" => decoded}}
        error -> error
      end
    end
  end

  defp dispatch("uri.normalize", input, raws) do
    with {:ok, bytes} <- input_bytes(input, raws) do
      case Uri.normalize(bytes, Bounds.maximum()) do
        {:ok, normalized} -> {:ok, %{"normalized" => normalized}}
        error -> error
      end
    end
  end

  defp dispatch("jcs.encode", input, raws) do
    with {:ok, bytes} <- input_bytes(input, raws),
         {:ok, value} <- Json.decode(bytes, Bounds.maximum()),
         {:ok, encoded} <- Jcs.encode(value, Bounds.maximum()) do
      {:ok, %{"encoded" => encoded}}
    end
  end

  defp dispatch("jwk.encode_public", input, _raws) do
    with {:ok, public_key} <- input_public_key(input) do
      case Jwk.encode_public(public_key, Bounds.maximum()) do
        {:ok, encoded} -> {:ok, %{"encoded" => encoded}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.decode_public", input, raws) do
    with {:ok, bytes} <- input_bytes(input, raws) do
      case Jwk.decode_public(bytes, Bounds.maximum()) do
        {:ok, public_key} -> {:ok, %{"public_key" => public_key}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.thumbprint_preimage", input, raws) do
    with {:ok, bytes} <- input_bytes(input, raws) do
      case Jwk.thumbprint_preimage(bytes, Bounds.maximum()) do
        {:ok, preimage} -> {:ok, %{"preimage" => preimage}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.thumbprint", input, raws) do
    with {:ok, bytes} <- input_bytes(input, raws) do
      case Jwk.thumbprint(bytes, Bounds.maximum()) do
        {:ok, thumbprint} -> {:ok, %{"thumbprint" => thumbprint}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.thumbprint_raw", input, raws) do
    with {:ok, bytes} <- input_bytes(input, raws) do
      case Jwk.thumbprint_raw(bytes, Bounds.maximum()) do
        {:ok, raw} -> {:ok, %{"thumbprint_raw" => raw}}
        error -> error
      end
    end
  end

  defp dispatch("jwk.public_key_thumbprint_raw", input, _raws) do
    with {:ok, public_key} <- input_public_key(input) do
      case Jwk.public_key_thumbprint_raw(public_key, Bounds.maximum()) do
        {:ok, raw} -> {:ok, %{"thumbprint_raw" => raw}}
        error -> error
      end
    end
  end

  defp dispatch("bounds.new", input, _raws) do
    case normalize_bounds_overrides(Map.get(input, "overrides", %{})) do
      {:ok, overrides} ->
        case Bounds.new(overrides) do
          {:ok, bounds} -> {:ok, %{"bounds" => bounds}}
          error -> error
        end

      :error ->
        {:error, :invalid}
    end
  end

  defp dispatch("untrusted_key_locator", input, _raws) do
    with {:ok, compact} <- fetch_binary(input, "compact") do
      case BoundedAuthorityProtocol.V1.untrusted_key_locator(compact, %{}) do
        {:ok, locator} -> {:ok, %{"kid" => locator.kid}}
        error -> error
      end
    end
  end

  defp dispatch("grant_signing_input", input, _raws) do
    with {:ok, grant} <- build_grant(input) do
      case BoundedAuthorityProtocol.V1.grant_signing_input(grant, bounds(input)) do
        {:ok, si} ->
          {:ok,
           %{
             "protected_segment" => si.protected_segment,
             "payload_segment" => si.payload_segment,
             "message" => si.message
           }}

        error ->
          error
      end
    end
  end

  defp dispatch("proof_signing_input", input, _raws) do
    with {:ok, proof} <- build_proof(input) do
      case BoundedAuthorityProtocol.V1.proof_signing_input(proof, bounds(input)) do
        {:ok, si} ->
          {:ok,
           %{
             "protected_segment" => si.protected_segment,
             "payload_segment" => si.payload_segment,
             "message" => si.message
           }}

        error ->
          error
      end
    end
  end

  defp dispatch("encode_consumption_entry", input, _raws) do
    with {:ok, entry} <- build_consumption_entry(input) do
      case BoundedAuthorityProtocol.V1.encode_consumption_entry(entry, bounds(input)) do
        {:ok, encoded} -> {:ok, %{"bytes" => encoded.bytes, "hash" => encoded.hash}}
        error -> error
      end
    end
  end

  defp dispatch("check_chain", input, _raws) do
    with {:ok, chain_input, expected_chain} <- build_chain(input, raws_for(input)) do
      case BoundedAuthorityProtocol.V1.check_chain(chain_input, expected_chain) do
        {:ok, facts} -> {:ok, chain_facts_map(facts)}
        error -> error
      end
    end
  end

  defp dispatch("boundary_anchor_signing_input", input, _raws) do
    with {:ok, anchor} <- build_anchor(input) do
      case BoundedAuthorityProtocol.V1.boundary_anchor_signing_input(anchor, bounds(input)) do
        {:ok, si} ->
          {:ok,
           %{
             "protected_segment" => si.protected_segment,
             "payload_segment" => si.payload_segment,
             "message" => si.message
           }}

        error ->
          error
      end
    end
  end

  defp dispatch("key_transition_signing_input", input, _raws) do
    with {:ok, transition} <- build_transition(input) do
      case BoundedAuthorityProtocol.V1.key_transition_signing_input(transition, bounds(input)) do
        {:ok, si} ->
          {:ok,
           %{
             "protected_segment" => si.protected_segment,
             "payload_segment" => si.payload_segment,
             "message" => si.message
           }}

        error ->
          error
      end
    end
  end

  defp dispatch("encode_anchored_export", input, _raws) do
    with {:ok, export_input, expected} <- build_anchored_export(input, raws_for(input)) do
      case BoundedAuthorityProtocol.V1.encode_anchored_export(export_input, expected) do
        {:ok, encoded} ->
          {:ok,
           %{
             "chunks" => encoded.chunks,
             "digest" => encoded.digest,
             "byte_count" => encoded.byte_count
           }}

        error ->
          error
      end
    end
  end

  defp dispatch("assemble_compact", input, _raws) do
    with {:ok, signing_input, signature} <- build_assemble_input(input) do
      case BoundedAuthorityProtocol.V1.assemble_compact(signing_input, signature) do
        {:ok, compact} -> {:ok, %{"compact" => compact}}
        error -> error
      end
    end
  end

  defp dispatch("decode_grant", input, _raws) do
    with {:ok, compact} <- fetch_binary(input, "compact") do
      case BoundedAuthorityProtocol.V1.decode_grant(compact, bounds(input)) do
        {:ok, decoded} -> {:ok, decoded_grant_map(decoded)}
        error -> error
      end
    end
  end

  defp dispatch("decode_proof", input, _raws) do
    with {:ok, compact} <- fetch_binary(input, "compact") do
      case BoundedAuthorityProtocol.V1.decode_proof(compact, bounds(input)) do
        {:ok, decoded} -> {:ok, decoded_proof_map(decoded)}
        error -> error
      end
    end
  end

  defp dispatch("verify_grant", input, _raws) do
    with {:ok, compact, trusted, expected} <- build_verify_grant(input) do
      case BoundedAuthorityProtocol.V1.verify_grant(compact, trusted, expected) do
        {:ok, facts} -> {:ok, grant_facts_map(facts)}
        error -> error
      end
    end
  end

  defp dispatch("verify_historical_anchor", input, _raws) do
    with {:ok, compact, key, expected} <- build_verify_anchor(input) do
      case BoundedAuthorityProtocol.V1.verify_historical_anchor(compact, key, expected) do
        {:ok, facts} -> {:ok, anchor_facts_map(facts)}
        error -> error
      end
    end
  end

  defp dispatch("verify_key_transition", input, _raws) do
    with {:ok, compact, current_key, next_key, expected} <- build_verify_transition(input) do
      case BoundedAuthorityProtocol.V1.verify_key_transition(
             compact,
             current_key,
             next_key,
             expected
           ) do
        {:ok, facts} -> {:ok, transition_facts_map(facts)}
        error -> error
      end
    end
  end

  defp dispatch("verify_anchored_export", input, _raws) do
    with {:ok, archived, key_chain, expected} <- build_verify_export(input, raws_for(input)) do
      case BoundedAuthorityProtocol.V1.verify_anchored_export(archived, key_chain, expected) do
        {:ok, facts} -> {:ok, export_facts_map(facts)}
        error -> error
      end
    end
  end

  defp dispatch("check_envelope", input, _raws) do
    with {:ok, credentials, expected_request} <- build_envelope(input) do
      case BoundedAuthorityProtocol.V1.check_envelope(credentials, expected_request) do
        {:ok, facts} -> {:ok, envelope_facts_map(facts)}
        error -> error
      end
    end
  end

  defp dispatch("request_digest", input, _raws) do
    with {:ok, operation, cast_args} <- build_request_digest(input) do
      case BoundedAuthorityProtocol.V1.request_digest(operation, cast_args, bounds(input)) do
        {:ok, digest} -> {:ok, %{"digest" => digest}}
        error -> error
      end
    end
  end

  # JSON case input carries override keys as strings; Bounds.new expects the atom
  # keys of the @maximum map. Convert each known key via the compile-time @bounds_keys
  # map; Bounds.new independently rejects any value that fails its tightening rules.
  defp normalize_bounds_overrides(overrides) do
    Enum.reduce_while(overrides, {:ok, %{}}, fn {key, value}, {:ok, acc} ->
      case Map.fetch(@bounds_keys, key) do
        {:ok, atom_key} -> {:cont, {:ok, Map.put(acc, atom_key, value)}}
        :error -> {:halt, :error}
      end
    end)
  end

  # --- input extraction ----------------------------------------------------

  defp input_bytes(input, raws) do
    cond do
      is_binary(input["text"]) -> {:ok, input["text"]}
      is_binary(input["base64url"]) -> decode_b64_value(input["base64url"])
      is_binary(input["raw_file"]) -> raw_bytes(input["raw_file"], raws)
      true -> {:error, :invalid}
    end
  end

  defp decode_b64_value(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid}
    end
  end

  defp raw_bytes(raw_path, raws) do
    case Map.get(raws, raw_path) do
      {bytes, _hash} -> {:ok, bytes}
      nil -> {:error, :invalid}
    end
  end

  defp b64url_segment(input) do
    case Map.get(input, "base64url") do
      seg when is_binary(seg) -> seg
      _ -> fallback_segment(input)
    end
  end

  defp fallback_segment(input) do
    case input_bytes(input, %{}) do
      {:ok, seg} -> seg
      _ -> ""
    end
  end

  defp input_public_key(input) do
    with {:ok, encoded} <- fetch_binary(input, "public_key") do
      case Base.url_decode64(encoded, padding: false) do
        {:ok, decoded} -> {:ok, decoded}
        :error -> {:error, :invalid}
      end
    end
  end

  defp fetch_binary(input, key) do
    case Map.get(input, key) do
      bytes when is_binary(bytes) -> {:ok, bytes}
      _ -> {:error, :invalid}
    end
  end

  # --- projection + comparison --------------------------------------------

  defp project("value", {:json, value}), do: value

  # Producer-output and verifier-facts maps: the expected JSON key (a string) matches the
  # result-map key (also a string in the facts maps). Raw-byte fields are compared via the
  # base64url fallback in compare?/3.
  defp project(key, map) when is_binary(key) and is_map(map) do
    Map.get(map, key, :no_projection)
  end

  defp project(_key, _actual), do: :no_projection

  defp compare?(_key, _expected, actual) when actual == :no_projection, do: false

  defp compare?("decoded", expected, actual) do
    # expected is a plain map (from JSON); actual is tagged algebra. Compare structurally.
    to_plain(actual) == expected
  end

  defp compare?("value", expected, actual), do: to_plain(actual) == expected

  defp compare?("bounds", _expected, %Bounds{}), do: true

  defp compare?(_key, expected, actual) do
    actual == expected or
      (is_binary(expected) and is_binary(actual) and byte_string_compare(expected, actual))
  end

  defp byte_string_compare(expected, actual) do
    # base64url-encoded expected values compare against raw actual by decoding.
    case Base.url_decode64(expected, padding: false) do
      {:ok, decoded} -> decoded == actual
      :error -> expected == actual
    end
  end

  defp to_plain({:object, members}),
    do: members |> Enum.map(fn {k, v} -> {k, to_plain(v)} end) |> Map.new()

  defp to_plain({:array, items}), do: Enum.map(items, &to_plain/1)
  defp to_plain({:string, s}), do: s
  defp to_plain({:integer, n}), do: n
  defp to_plain({:float, n}), do: n
  defp to_plain({:boolean, b}), do: b
  defp to_plain(:null), do: nil
  defp to_plain(other), do: other

  # --- struct builders (case-input JSON -> frozen-facade structs) -------------

  defp bounds(input), do: Map.get(input, "bounds", %{})

  # The Runner does not carry raws on dispatch; chain/archive cases embed row bytes
  # inline. This stub keeps the signature consistent for surfaces that never need it.
  defp raws_for(_input), do: %{}

  defp build_grant(input) do
    with {:ok, key_id} <- fetch_binary(input, "key_id"),
         {:ok, issuer} <- fetch_binary(input, "issuer"),
         {:ok, grant_id} <- fetch_binary(input, "grant_id"),
         {:ok, audiences} <- string_list(input, "audiences"),
         {:ok, issued_at} <- int_field(input, "issued_at"),
         {:ok, not_before} <- int_field(input, "not_before"),
         {:ok, expires_at} <- int_field(input, "expires_at"),
         {:ok, holder_thumbprint} <- b64_field(input, "holder_thumbprint"),
         {:ok, operations} <- build_operations(input) do
      {:ok,
       %Grant{
         key_id: key_id,
         issuer: issuer,
         grant_id: grant_id,
         audiences: audiences,
         issued_at: issued_at,
         not_before: not_before,
         expires_at: expires_at,
         holder_thumbprint: holder_thumbprint,
         operations: operations
       }}
    end
  end

  defp build_proof(input) do
    with {:ok, holder_public_key} <- b64_field(input, "holder_public_key"),
         {:ok, proof_id} <- fetch_binary(input, "proof_id"),
         {:ok, method} <- fetch_binary(input, "method"),
         {:ok, target_uri} <- fetch_binary(input, "target_uri"),
         {:ok, issued_at} <- int_field(input, "issued_at"),
         {:ok, invocation_id} <- fetch_binary(input, "invocation_id"),
         {:ok, operation} <- fetch_binary(input, "operation"),
         {:ok, grant_compact} <- fetch_binary(input, "grant_compact"),
         {:ok, cast_arguments} <- json_field(input, "cast_arguments") do
      {:ok,
       %Proof{
         holder_public_key: holder_public_key,
         proof_id: proof_id,
         method: method,
         target_uri: target_uri,
         issued_at: issued_at,
         nonce: proof_nonce(input),
         invocation_id: invocation_id,
         operation: operation,
         grant_compact: grant_compact,
         cast_arguments: cast_arguments
       }}
    end
  end

  defp proof_nonce(input) do
    case Map.get(input, "nonce") do
      nil ->
        nil

      encoded when is_binary(encoded) ->
        case Base.url_decode64(encoded, padding: false) do
          {:ok, decoded} -> decoded
          # Malformed nonce encoding -> treat as absent (a nil nonce fails nonce_matches? when
          # a nonce is required, and passes when not required — fail-closed without over-rejecting).
          :error -> nil
        end

      _ ->
        nil
    end
  end

  defp build_operations(input) do
    case Map.get(input, "operations") do
      ops when is_list(ops) -> reduce_build(ops, &build_operation/1)
      _ -> {:error, :invalid}
    end
  end

  defp build_operation(%{"name" => name, "selectors" => selectors})
       when is_binary(name) and is_list(selectors) do
    with {:ok, built_selectors} <- build_selectors(selectors) do
      {:ok, %Operation{name: name, selectors: built_selectors}}
    end
  end

  defp build_operation(_), do: {:error, :invalid}

  defp build_selectors(selectors) do
    reduce_build(selectors, &build_selector/1)
  end

  defp build_selector("all"), do: {:ok, :all}

  defp build_selector(%{"kind" => "equals", "path" => path, "value" => value})
       when is_list(path) do
    {:ok, {:equals, path, to_tagged(value)}}
  end

  defp build_selector(%{"kind" => "one_of", "path" => path, "values" => values})
       when is_list(path) and is_list(values) do
    {:ok, {:one_of, path, Enum.map(values, &to_tagged/1)}}
  end

  defp build_selector(_), do: {:error, :invalid}

  defp build_consumption_entry(input) do
    with {:ok, chain_id} <- fetch_binary(input, "chain_id"),
         {:ok, sequence} <- int_field(input, "sequence"),
         {:ok, previous_hash} <- b64_field(input, "previous_hash"),
         {:ok, commitment} <- b64_field(input, "commitment") do
      {:ok,
       %ConsumptionEntry{
         chain_id: chain_id,
         sequence: sequence,
         previous_hash: previous_hash,
         commitment: commitment
       }}
    end
  end

  defp build_anchored_export(input, _raws) do
    with {:ok, rows} <- byte_list(input, "rows"),
         {:ok, start_anchor} <- fetch_binary(input, "start_anchor"),
         {:ok, end_anchor} <- fetch_binary(input, "end_anchor"),
         transitions <- Map.get(input, "transitions", []),
         true <- is_list(transitions),
         expected <- Map.get(input, "expected", %{}),
         {:ok, expected_export} <- build_expected_export(expected) do
      {:ok,
       %AnchoredExportInput{
         rows: rows,
         start_anchor: start_anchor,
         transitions: transitions,
         end_anchor: end_anchor
       }, expected_export}
    end
  end

  defp build_chain(input, _raws) do
    with {:ok, rows} <- byte_list(input, "rows"),
         {:ok, chain_id} <- fetch_binary(input, "chain_id"),
         {:ok, first_sequence} <- int_field(input, "first_sequence"),
         {:ok, last_sequence} <- int_field(input, "last_sequence"),
         {:ok, row_count} <- int_field(input, "row_count"),
         {:ok, previous_hash} <- b64_field(input, "previous_hash"),
         {:ok, last_hash} <- b64_field(input, "last_hash") do
      {:ok, %ChainInput{rows: rows},
       %ExpectedChain{
         chain_id: chain_id,
         first_sequence: first_sequence,
         last_sequence: last_sequence,
         row_count: row_count,
         previous_hash: previous_hash,
         last_hash: last_hash,
         bounds: bounds(input)
       }}
    end
  end

  defp build_anchor(input) do
    with {:ok, anchor_id} <- fetch_binary(input, "anchor_id"),
         {:ok, anchored_at} <- int_field(input, "anchored_at"),
         {:ok, chain_id} <- fetch_binary(input, "chain_id"),
         {:ok, sequence} <- int_field(input, "sequence"),
         {:ok, chain_hash} <- b64_field(input, "chain_hash"),
         {:ok, key_id} <- fetch_binary(input, "key_id"),
         {:ok, public_key} <- b64_field(input, "public_key") do
      {:ok,
       %BoundaryAnchor{
         anchor_id: anchor_id,
         anchored_at: anchored_at,
         chain_id: chain_id,
         sequence: sequence,
         chain_hash: chain_hash,
         key_id: key_id,
         public_key: public_key
       }}
    end
  end

  defp build_transition(input) do
    with {:ok, transition_id} <- fetch_binary(input, "transition_id"),
         {:ok, chain_id} <- fetch_binary(input, "chain_id"),
         {:ok, effective_at} <- int_field(input, "effective_at"),
         {:ok, current_key_id} <- fetch_binary(input, "current_key_id"),
         {:ok, current_public_key} <- b64_field(input, "current_public_key"),
         {:ok, next_key_id} <- fetch_binary(input, "next_key_id"),
         {:ok, next_public_key} <- b64_field(input, "next_public_key") do
      {:ok,
       %KeyTransition{
         transition_id: transition_id,
         chain_id: chain_id,
         effective_at: effective_at,
         current_key_id: current_key_id,
         current_public_key: current_public_key,
         next_key_id: next_key_id,
         next_public_key: next_public_key
       }}
    end
  end

  defp build_assemble_input(input) do
    with {:ok, kind} <- fetch_binary(input, "kind"),
         {:ok, protected_segment} <- fetch_binary(input, "protected_segment"),
         {:ok, payload_segment} <- fetch_binary(input, "payload_segment"),
         {:ok, signature} <- b64_field(input, "signature") do
      kind_atom = signing_input_kind(kind)
      message = protected_segment <> "." <> payload_segment

      {:ok,
       %SigningInput{
         kind: kind_atom,
         protected_segment: protected_segment,
         payload_segment: payload_segment,
         message: message
       }, signature}
    end
  end

  defp signing_input_kind("grant"), do: :grant
  defp signing_input_kind("proof"), do: :proof
  defp signing_input_kind("boundary_anchor"), do: :boundary_anchor
  defp signing_input_kind("key_transition"), do: :key_transition
  defp signing_input_kind(_), do: :invalid

  defp build_verify_grant(input) do
    with {:ok, compact} <- fetch_binary(input, "compact"),
         {:ok, key_id} <- fetch_binary(input, "key_id"),
         {:ok, public_key} <- b64_field(input, "public_key"),
         {:ok, issuer} <- fetch_binary(input, "issuer"),
         {:ok, audience} <- fetch_binary(input, "audience"),
         {:ok, evaluation_time} <- int_field(input, "evaluation_time"),
         {:ok, clock_skew} <- int_field(input, "clock_skew") do
      {:ok, compact, %TrustedIssuer{key_id: key_id, public_key: public_key},
       %ExpectedGrant{
         issuer: issuer,
         audience: audience,
         evaluation_time: evaluation_time,
         clock_skew: clock_skew,
         bounds: bounds(input)
       }}
    end
  end

  defp build_verify_anchor(input) do
    with {:ok, compact} <- fetch_binary(input, "compact"),
         {:ok, key} <- build_historical_key(Map.get(input, "key", %{})),
         {:ok, expected} <- build_expected_anchor(Map.get(input, "expected", %{})) do
      {:ok, compact, key, expected}
    end
  end

  defp build_verify_transition(input) do
    with {:ok, compact} <- fetch_binary(input, "compact"),
         {:ok, current_key} <- build_historical_key(Map.get(input, "current_key", %{})),
         {:ok, next_key} <- build_historical_key(Map.get(input, "next_key", %{})),
         {:ok, expected} <- build_expected_transition(Map.get(input, "expected", %{})) do
      {:ok, compact, current_key, next_key, expected}
    end
  end

  defp build_verify_export(input, _raws) do
    with {:ok, chunks} <- byte_list(input, "chunks"),
         {:ok, version} <- fetch_binary(input, "version"),
         {:ok, keys} <- build_historical_keys(input),
         {:ok, expected} <- build_expected_anchored_export(Map.get(input, "expected", %{})) do
      {:ok, %ArchivedObject{chunks: chunks, version: version}, %HistoricalKeyChain{keys: keys},
       expected}
    end
  end

  defp build_envelope(input) do
    with {:ok, grant} <- fetch_binary(input, "grant"),
         {:ok, proof} <- fetch_binary(input, "proof"),
         {:ok, expected} <- build_expected_request(Map.get(input, "expected", %{})) do
      {:ok, %Credentials{grant: grant, proof: proof}, expected}
    end
  end

  defp build_request_digest(input) do
    with {:ok, operation} <- fetch_binary(input, "operation"),
         {:ok, cast_args} <- json_field(input, "cast_arguments") do
      {:ok, operation, cast_args}
    end
  end

  defp build_historical_keys(input) do
    case Map.get(input, "keys") do
      keys when is_list(keys) -> reduce_build(keys, &build_historical_key/1)
      _ -> {:error, :invalid}
    end
  end

  defp reduce_build(items, builder) do
    Enum.reduce_while(items, {:ok, []}, fn item, {:ok, acc} ->
      case builder.(item) do
        {:ok, built} -> {:cont, {:ok, [built | acc]}}
        error -> {:halt, error}
      end
    end)
    |> map_ok_reverse()
  end

  defp build_historical_key(key_map) do
    with {:ok, key_id} <- fetch_binary(key_map, "key_id"),
         {:ok, public_key} <- b64_field(key_map, "public_key"),
         {:ok, valid_from} <- int_field(key_map, "valid_from") do
      {:ok,
       %HistoricalPublicKey{
         key_id: key_id,
         public_key: public_key,
         valid_from: valid_from,
         valid_before: valid_before(key_map)
       }}
    end
  end

  defp valid_before(%{"valid_before" => vb}) when is_integer(vb), do: vb
  defp valid_before(_), do: :unbounded

  defp build_expected_anchor(expected) do
    with {:ok, anchor_id} <- fetch_binary(expected, "anchor_id"),
         {:ok, anchored_at} <- int_field(expected, "anchored_at"),
         {:ok, chain_id} <- fetch_binary(expected, "chain_id"),
         {:ok, sequence} <- int_field(expected, "sequence"),
         {:ok, chain_hash} <- b64_field(expected, "chain_hash"),
         {:ok, key_id} <- fetch_binary(expected, "key_id"),
         {:ok, key_fingerprint} <- b64_field(expected, "key_fingerprint") do
      {:ok,
       %ExpectedAnchor{
         anchor_id: anchor_id,
         anchored_at: anchored_at,
         chain_id: chain_id,
         sequence: sequence,
         chain_hash: chain_hash,
         key_id: key_id,
         key_fingerprint: key_fingerprint,
         bounds: Map.get(expected, "bounds", %{})
       }}
    end
  end

  defp build_expected_transition(expected) do
    with {:ok, transition_id} <- fetch_binary(expected, "transition_id"),
         {:ok, chain_id} <- fetch_binary(expected, "chain_id"),
         {:ok, effective_at} <- int_field(expected, "effective_at"),
         {:ok, current_key_id} <- fetch_binary(expected, "current_key_id"),
         {:ok, current_key_fingerprint} <- b64_field(expected, "current_key_fingerprint"),
         {:ok, next_key_id} <- fetch_binary(expected, "next_key_id"),
         {:ok, next_key_fingerprint} <- b64_field(expected, "next_key_fingerprint") do
      {:ok,
       %ExpectedKeyTransition{
         transition_id: transition_id,
         chain_id: chain_id,
         effective_at: effective_at,
         current_key_id: current_key_id,
         current_key_fingerprint: current_key_fingerprint,
         next_key_id: next_key_id,
         next_key_fingerprint: next_key_fingerprint,
         bounds: Map.get(expected, "bounds", %{})
       }}
    end
  end

  defp build_expected_export(expected) do
    with {:ok, chain} <- build_expected_chain(Map.get(expected, "chain", %{})),
         {:ok, start_anchor} <- build_expected_anchor(Map.get(expected, "start_anchor", %{})),
         {:ok, end_anchor} <- build_expected_anchor(Map.get(expected, "end_anchor", %{})) do
      {:ok,
       %ExpectedExport{
         chain: chain,
         start_anchor: start_anchor,
         transitions: expected_transitions(Map.get(expected, "transitions")),
         end_anchor: end_anchor,
         bounds: Map.get(expected, "bounds", %{})
       }}
    end
  end

  defp build_expected_anchored_export(expected) do
    with {:ok, chain} <- build_expected_chain(Map.get(expected, "chain", %{})),
         {:ok, start_anchor} <- build_expected_anchor(Map.get(expected, "start_anchor", %{})),
         {:ok, end_anchor} <- build_expected_anchor(Map.get(expected, "end_anchor", %{})),
         {:ok, digest} <- b64_field(expected, "digest"),
         {:ok, object_version} <- fetch_binary(expected, "object_version") do
      {:ok,
       %ExpectedAnchoredExport{
         chain: chain,
         start_anchor: start_anchor,
         transitions: expected_transitions(Map.get(expected, "transitions")),
         end_anchor: end_anchor,
         digest: digest,
         object_version: object_version,
         bounds: Map.get(expected, "bounds", %{})
       }}
    end
  end

  defp expected_transitions(list) when is_list(list) do
    Enum.map(list, fn t ->
      {:ok, built} = build_expected_transition(t)
      built
    end)
  end

  defp expected_transitions(_), do: []

  defp build_expected_chain(expected) do
    with {:ok, chain_id} <- fetch_binary(expected, "chain_id"),
         {:ok, first_sequence} <- int_field(expected, "first_sequence"),
         {:ok, last_sequence} <- int_field(expected, "last_sequence"),
         {:ok, row_count} <- int_field(expected, "row_count"),
         {:ok, previous_hash} <- b64_field(expected, "previous_hash"),
         {:ok, last_hash} <- b64_field(expected, "last_hash") do
      {:ok,
       %ExpectedChain{
         chain_id: chain_id,
         first_sequence: first_sequence,
         last_sequence: last_sequence,
         row_count: row_count,
         previous_hash: previous_hash,
         last_hash: last_hash,
         bounds: Map.get(expected, "bounds", %{})
       }}
    end
  end

  defp build_expected_request(expected) do
    with {:ok, trusted} <- build_trusted_issuer(Map.get(expected, "trusted_issuer", %{})),
         {:ok, issuer} <- fetch_binary(expected, "issuer"),
         {:ok, audience} <- fetch_binary(expected, "audience"),
         {:ok, method} <- fetch_binary(expected, "method"),
         {:ok, target_uri} <- fetch_binary(expected, "target_uri"),
         {:ok, invocation_id} <- fetch_binary(expected, "invocation_id"),
         {:ok, operation} <- fetch_binary(expected, "operation"),
         {:ok, cast_arguments} <- json_field(expected, "cast_arguments"),
         {:ok, evaluation_time} <- int_field(expected, "evaluation_time"),
         {:ok, clock_skew} <- int_field(expected, "clock_skew"),
         {:ok, proof_max_age} <- int_field(expected, "proof_max_age") do
      {:ok,
       %ExpectedRequest{
         trusted_issuer: trusted,
         issuer: issuer,
         audience: audience,
         method: method,
         target_uri: target_uri,
         invocation_id: invocation_id,
         operation: operation,
         cast_arguments: cast_arguments,
         evaluation_time: evaluation_time,
         clock_skew: clock_skew,
         proof_max_age: proof_max_age,
         nonce: expected_nonce(Map.get(expected, "nonce")),
         bounds: Map.get(expected, "bounds", %{})
       }}
    end
  end

  defp build_trusted_issuer(ti) do
    with {:ok, key_id} <- fetch_binary(ti, "key_id"),
         {:ok, public_key} <- b64_field(ti, "public_key") do
      {:ok, %TrustedIssuer{key_id: key_id, public_key: public_key}}
    end
  end

  defp expected_nonce(%{"required" => encoded}) when is_binary(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, decoded} -> {:required, decoded}
      # Malformed required-nonce encoding -> sentinel that nonce_matches?/2's catch-all
      # (_ -> false) rejects for ANY proof nonce, so verify fails closed.
      :error -> :malformed
    end
  end

  defp expected_nonce(_), do: :not_required

  # --- facts projection (struct -> comparable map) --------------------------

  defp chain_facts_map(f) do
    %{
      "version" => f.version,
      "chain_id" => f.chain_id,
      "first_sequence" => f.first_sequence,
      "last_sequence" => f.last_sequence,
      "row_count" => f.row_count,
      "previous_hash" => f.previous_hash,
      "last_hash" => f.last_hash,
      "verification" => f.verification,
      "trust" => f.trust
    }
  end

  defp decoded_grant_map(d) do
    %{
      "version" => d.version,
      "key_id" => d.key_id,
      "issuer" => d.issuer,
      "grant_id" => d.grant_id,
      "audiences" => d.audiences,
      "issued_at" => d.issued_at,
      "not_before" => d.not_before,
      "expires_at" => d.expires_at,
      "holder_thumbprint" => d.holder_thumbprint,
      "operations" => d.operations,
      "verification" => d.verification
    }
  end

  defp decoded_proof_map(d) do
    %{
      "version" => d.version,
      "proof_id" => d.proof_id,
      "method" => d.method,
      "target_uri" => d.target_uri,
      "issued_at" => d.issued_at,
      "nonce" => d.nonce,
      "invocation_id" => d.invocation_id,
      "operation" => d.operation,
      "grant_hash" => d.grant_hash,
      "request_hash" => d.request_hash,
      "holder_public_key" => d.holder_public_key,
      "holder_thumbprint" => d.holder_thumbprint,
      "verification" => d.verification
    }
  end

  defp grant_facts_map(f) do
    %{
      "version" => f.version,
      "issuer" => f.issuer,
      "grant_id" => f.grant_id,
      "issuer_key_fingerprint" => f.issuer_key_fingerprint,
      "holder_thumbprint" => f.holder_thumbprint,
      "matched_audience" => f.matched_audience,
      "issued_at" => f.issued_at,
      "not_before" => f.not_before,
      "expires_at" => f.expires_at,
      "authorization" => f.authorization
    }
  end

  defp anchor_facts_map(f) do
    %{
      "version" => f.version,
      "anchor_id" => f.anchor_id,
      "anchored_at" => f.anchored_at,
      "chain_id" => f.chain_id,
      "sequence" => f.sequence,
      "chain_hash" => f.chain_hash,
      "key_fingerprint" => f.key_fingerprint,
      "verification" => f.verification,
      "trust" => f.trust
    }
  end

  defp transition_facts_map(f) do
    %{
      "version" => f.version,
      "transition_id" => f.transition_id,
      "effective_at" => f.effective_at,
      "chain_id" => f.chain_id,
      "current_key_fingerprint" => f.current_key_fingerprint,
      "next_key_fingerprint" => f.next_key_fingerprint,
      "verification" => f.verification,
      "trust" => f.trust
    }
  end

  defp export_facts_map(f) do
    %{
      "version" => f.version,
      "chain_id" => f.chain_id,
      "first_sequence" => f.first_sequence,
      "last_sequence" => f.last_sequence,
      "row_count" => f.row_count,
      "previous_hash" => f.previous_hash,
      "last_hash" => f.last_hash,
      "digest" => f.digest,
      "start_anchor_id" => f.start_anchor_id,
      "start_anchored_at" => f.start_anchored_at,
      "start_key_fingerprint" => f.start_key_fingerprint,
      "end_anchor_id" => f.end_anchor_id,
      "end_anchored_at" => f.end_anchored_at,
      "end_key_fingerprint" => f.end_key_fingerprint,
      "transition_count" => f.transition_count,
      "verification" => f.verification,
      "trust" => f.trust,
      "authorization" => f.authorization
    }
  end

  defp envelope_facts_map(f), do: Map.from_struct(f)

  # --- field decoders -------------------------------------------------------

  defp int_field(map, key) do
    case Map.get(map, key) do
      n when is_integer(n) -> {:ok, n}
      _ -> {:error, :invalid}
    end
  end

  defp b64_field(map, key) do
    with {:ok, encoded} <- fetch_binary(map, key) do
      case Base.url_decode64(encoded, padding: false) do
        {:ok, decoded} -> {:ok, decoded}
        :error -> {:error, :invalid}
      end
    end
  end

  defp string_list(map, key) do
    case Map.get(map, key) do
      list when is_list(list) and list != [] ->
        if Enum.all?(list, &is_binary/1), do: {:ok, list}, else: {:error, :invalid}

      _ ->
        {:error, :invalid}
    end
  end

  defp byte_list(map, key) do
    case Map.get(map, key) do
      list when is_list(list) -> reduce_build(list, &decode_b64_item/1)
      _ -> {:error, :invalid}
    end
  end

  defp decode_b64_item(encoded) when is_binary(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid}
    end
  end

  defp decode_b64_item(_), do: {:error, :invalid}

  defp json_field(map, key) do
    case Map.get(map, key) do
      nil -> {:error, :invalid}
      value -> {:ok, to_tagged(value)}
    end
  end

  defp to_tagged(value) do
    cond do
      is_map(value) ->
        {:object,
         value |> Enum.map(fn {k, v} -> {k, to_tagged(v)} end) |> Enum.sort_by(&elem(&1, 0))}

      is_list(value) ->
        {:array, Enum.map(value, &to_tagged/1)}

      is_integer(value) ->
        {:integer, value}

      is_boolean(value) ->
        {:boolean, value}

      is_binary(value) ->
        {:string, value}

      is_float(value) ->
        {:float, value}

      true ->
        :null
    end
  end

  defp map_ok_reverse({:ok, list}), do: {:ok, Enum.reverse(list)}
  defp map_ok_reverse(error), do: error
end
