defmodule BoundedAuthorityProtocol.V1.AnchoredExportCodec do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1.AnchoredExportFacts
  alias BoundedAuthorityProtocol.V1.AnchoredExportInput
  alias BoundedAuthorityProtocol.V1.ArchivedObject
  alias BoundedAuthorityProtocol.V1.Base64Url
  alias BoundedAuthorityProtocol.V1.BoundaryAnchorCodec
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.ChainInput
  alias BoundedAuthorityProtocol.V1.ConsumptionChain
  alias BoundedAuthorityProtocol.V1.ContextValidation
  alias BoundedAuthorityProtocol.V1.EncodedAnchoredExport
  alias BoundedAuthorityProtocol.V1.ExpectedAnchor
  alias BoundedAuthorityProtocol.V1.ExpectedAnchoredExport
  alias BoundedAuthorityProtocol.V1.ExpectedChain
  alias BoundedAuthorityProtocol.V1.ExpectedExport
  alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
  alias BoundedAuthorityProtocol.V1.FixedBytes
  alias BoundedAuthorityProtocol.V1.HistoricalKeyChain
  alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
  alias BoundedAuthorityProtocol.V1.Jcs
  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityProtocol.V1.Jwk
  alias BoundedAuthorityProtocol.V1.KeyTransitionCodec

  @prefix "BAP1-ARCHIVE\0EXPORT\0"
  @header_keys ~w(chain_id first_sequence last_hash last_sequence previous_hash row_count transition_count v)

  @spec encode(AnchoredExportInput.t(), ExpectedExport.t()) ::
          {:ok, EncodedAnchoredExport.t()} | {:error, :invalid}
  def encode(%AnchoredExportInput{} = input, %ExpectedExport{} = expected) do
    with {:ok, bounds} <- Bounds.coerce(expected.bounds),
         :ok <- validate_expected_export(expected, bounds),
         {:ok, _facts} <-
           ConsumptionChain.check(
             %ChainInput{rows: input.rows},
             %{expected.chain | bounds: bounds}
           ),
         {:ok, start_parsed} <- BoundaryAnchorCodec.parse(input.start_anchor, bounds),
         true <- anchor_matches?(start_parsed, expected.start_anchor),
         {:ok, end_parsed} <- BoundaryAnchorCodec.parse(input.end_anchor, bounds),
         true <- anchor_matches?(end_parsed, expected.end_anchor),
         {:ok, transition_parsed} <-
           parse_expected_transitions(
             input.transitions,
             expected.transitions,
             bounds,
             0,
             []
           ),
         :ok <-
           validate_expected_key_path(
             expected.start_anchor,
             expected.transitions,
             expected.end_anchor
           ),
         {:ok, header} <- Jcs.encode(header_json(expected.chain, transition_parsed), bounds),
         true <- byte_size(header) <= bounds.archive_header_bytes,
         {:ok, chunks} <-
           build_chunks(
             header,
             input.start_anchor,
             input.transitions,
             input.rows,
             input.end_anchor,
             bounds
           ),
         {:ok, _chunk_count, byte_count} <- validate_chunks(chunks, bounds, 0, 0),
         digest <- hash_chunks(chunks) do
      {:ok,
       %EncodedAnchoredExport{
         chunks: chunks,
         digest: digest,
         byte_count: byte_count
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def encode(_input, _expected), do: {:error, :invalid}

  @spec verify(ArchivedObject.t(), HistoricalKeyChain.t(), ExpectedAnchoredExport.t()) ::
          {:ok, AnchoredExportFacts.t()} | {:error, :invalid}
  def verify(
        %ArchivedObject{} = archived,
        %HistoricalKeyChain{} = key_chain,
        %ExpectedAnchoredExport{} = expected
      ) do
    with {:ok, bounds} <- Bounds.coerce(expected.bounds),
         :ok <- validate_expected_anchored_export(expected, bounds),
         :ok <-
           validate_historical_key_shapes(
             key_chain.keys,
             proper_length(expected.transitions, 0) + 1,
             bounds,
             0
           ),
         :ok <- validate_object_versions(archived.version, expected.object_version, bounds),
         {:ok, _chunk_count, _byte_count} <-
           validate_chunks(archived.chunks, bounds, 0, 0),
         digest <- hash_chunks(archived.chunks),
         true <- FixedBytes.equal?(digest, expected.digest),
         {:ok, parsed} <- parse_archive(archived.chunks, bounds),
         parsed_header = parsed.header,
         expected_chain = expected.chain,
         true <- header_matches?(parsed_header, expected_chain, expected.transitions),
         true <- anchor_matches?(parsed.start_anchor_parsed, expected.start_anchor),
         true <- anchor_matches?(parsed.end_anchor_parsed, expected.end_anchor),
         {:ok, _parsed_transitions} <-
           compare_parsed_transitions(
             parsed.transition_parsed,
             expected.transitions,
             []
           ),
         :ok <-
           validate_expected_key_path(
             expected.start_anchor,
             expected.transitions,
             expected.end_anchor
           ),
         :ok <-
           validate_key_chain(
             key_chain.keys,
             parsed_header.transition_count + 1,
             bounds,
             [],
             0
           ),
         {:ok, start_key, remaining_keys} <- take_first_key(key_chain.keys),
         {:ok, start_facts} <-
           BoundaryAnchorCodec.verify(
             parsed.start_anchor,
             start_key,
             %{expected.start_anchor | bounds: bounds}
           ),
         {:ok, end_key, last_transition_at, transition_count} <-
           verify_transitions(
             parsed.transitions,
             remaining_keys,
             start_key,
             expected.transitions,
             bounds,
             start_facts.anchored_at,
             0
           ),
         {:ok, end_facts} <-
           BoundaryAnchorCodec.verify(
             parsed.end_anchor,
             end_key,
             %{expected.end_anchor | bounds: bounds}
           ),
         true <- chronological_end?(end_facts.anchored_at, last_transition_at),
         {:ok, _chain_facts} <-
           ConsumptionChain.check(
             %ChainInput{rows: parsed.rows},
             %{expected_chain | bounds: bounds}
           ),
         true <- authenticated_boundaries?(start_facts, end_facts, expected_chain) do
      {:ok,
       %AnchoredExportFacts{
         version: 1,
         chain_id: expected_chain.chain_id,
         first_sequence: expected_chain.first_sequence,
         last_sequence: expected_chain.last_sequence,
         row_count: expected_chain.row_count,
         previous_hash: expected_chain.previous_hash,
         last_hash: expected_chain.last_hash,
         digest: digest,
         start_anchor_id: start_facts.anchor_id,
         start_anchored_at: start_facts.anchored_at,
         start_key_fingerprint: start_facts.key_fingerprint,
         end_anchor_id: end_facts.anchor_id,
         end_anchored_at: end_facts.anchored_at,
         end_key_fingerprint: end_facts.key_fingerprint,
         transition_count: transition_count,
         verification: :anchored_export,
         trust: :not_evaluated,
         authorization: :not_evaluated
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  def verify(_archived, _key_chain, _expected), do: {:error, :invalid}

  defp parse_archive(chunks, bounds) do
    state = {<<>>, chunks}

    with {:ok, @prefix, state} <- read_exact(state, byte_size(@prefix)),
         {:ok, header_bytes, state} <- read_frame(state, bounds.archive_header_bytes),
         {:ok, header} <- parse_header(header_bytes, bounds),
         {:ok, start_anchor, state} <- read_frame(state, bounds.anchor_bytes),
         {:ok, start_anchor_parsed} <- BoundaryAnchorCodec.parse(start_anchor, bounds),
         {:ok, transitions, transition_parsed, state} <-
           read_transition_frames(state, header.transition_count, bounds, [], []),
         {:ok, rows, state} <- read_row_frames(state, header.row_count, bounds, []),
         {:ok, end_anchor, state} <- read_frame(state, bounds.anchor_bytes),
         {:ok, end_anchor_parsed} <- BoundaryAnchorCodec.parse(end_anchor, bounds),
         true <- eof?(state) do
      {:ok,
       %{
         header: header,
         start_anchor: start_anchor,
         start_anchor_parsed: start_anchor_parsed,
         transitions: transitions,
         transition_parsed: transition_parsed,
         rows: rows,
         end_anchor: end_anchor,
         end_anchor_parsed: end_anchor_parsed
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp parse_header(bytes, bounds) do
    with {:ok, {:object, members}} <- Json.decode(bytes, bounds),
         {:ok, header} <- closed_map(members, @header_keys),
         {:integer, 1} <- header["v"],
         {:string, chain_id} <- header["chain_id"],
         {:integer, first_sequence} <- header["first_sequence"],
         {:integer, last_sequence} <- header["last_sequence"],
         {:integer, row_count} <- header["row_count"],
         {:integer, transition_count} <- header["transition_count"],
         {:string, previous_encoded} <- header["previous_hash"],
         {:ok, previous_hash} <- Base64Url.decode(previous_encoded, bounds),
         {:string, last_encoded} <- header["last_hash"],
         {:ok, last_hash} <- Base64Url.decode(last_encoded, bounds),
         true <- valid_header_range?(first_sequence, last_sequence, row_count, bounds),
         true <- transition_count >= 0 and transition_count <= bounds.key_transitions,
         true <- byte_size(previous_hash) == bounds.digest_bytes,
         true <- byte_size(last_hash) == bounds.digest_bytes,
         {:ok, canonical} <- Jcs.encode({:object, members}, bounds),
         true <- bytes == canonical do
      {:ok,
       %{
         chain_id: chain_id,
         first_sequence: first_sequence,
         last_sequence: last_sequence,
         row_count: row_count,
         transition_count: transition_count,
         previous_hash: previous_hash,
         last_hash: last_hash
       }}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp valid_header_range?(first_sequence, last_sequence, row_count, bounds) do
    valid_header_sequences?(first_sequence, last_sequence, bounds) and
      valid_header_count?(row_count, first_sequence, last_sequence, bounds)
  end

  defp valid_header_sequences?(first_sequence, last_sequence, bounds),
    do:
      is_integer(first_sequence) and first_sequence > 0 and
        first_sequence <= bounds.integer_magnitude and is_integer(last_sequence) and
        last_sequence >= first_sequence and last_sequence <= bounds.integer_magnitude

  defp valid_header_count?(row_count, first_sequence, last_sequence, bounds),
    do:
      is_integer(row_count) and row_count > 0 and row_count <= bounds.chain_rows and
        row_count == last_sequence - first_sequence + 1

  defp read_transition_frames(state, 0, _bounds, compacts, parsed),
    do: {:ok, reverse(compacts), reverse(parsed), state}

  defp read_transition_frames(state, remaining, bounds, compacts, parsed)
       when remaining > 0 do
    with {:ok, compact, next_state} <- read_frame(state, bounds.anchor_bytes),
         {:ok, transition} <- KeyTransitionCodec.parse(compact, bounds) do
      read_transition_frames(
        next_state,
        remaining - 1,
        bounds,
        [compact | compacts],
        [transition | parsed]
      )
    else
      _failure -> {:error, :invalid}
    end
  end

  defp read_row_frames(state, 0, _bounds, rows), do: {:ok, reverse(rows), state}

  defp read_row_frames(state, remaining, bounds, rows) when remaining > 0 do
    case read_frame(state, bounds.chain_row_bytes) do
      {:ok, row, next_state} ->
        read_row_frames(next_state, remaining - 1, bounds, [row | rows])

      _failure ->
        {:error, :invalid}
    end
  end

  defp read_frame(state, maximum) do
    with {:ok, <<length::unsigned-big-integer-size(32)>>, next_state} <-
           read_exact(state, 4),
         true <- length > 0 and length <= maximum,
         {:ok, bytes, final_state} <- read_exact(next_state, length) do
      {:ok, bytes, final_state}
    else
      _failure -> {:error, :invalid}
    end
  end

  defp read_exact(state, count) when count >= 0, do: read_exact(state, count, [])

  defp read_exact({<<>>, [next | rest]}, count, accumulator)
       when is_binary(next) and byte_size(next) > 0,
       do: read_exact({next, rest}, count, accumulator)

  defp read_exact({current, rest}, count, accumulator)
       when is_binary(current) and byte_size(current) >= count do
    <<part::binary-size(^count), remaining::binary>> = current
    {:ok, :erlang.iolist_to_binary(reverse([part | accumulator])), {remaining, rest}}
  end

  defp read_exact({current, rest}, count, accumulator)
       when is_binary(current) and byte_size(current) > 0 do
    read_exact({<<>>, rest}, count - byte_size(current), [current | accumulator])
  end

  defp read_exact(_state, _count, _accumulator), do: {:error, :invalid}

  defp eof?({<<>>, []}), do: true
  defp eof?(_state), do: false

  defp validate_chunks([], _bounds, 0, _bytes), do: {:error, :invalid}

  defp validate_chunks([], _bounds, count, bytes), do: {:ok, count, bytes}

  defp validate_chunks([chunk | rest], bounds, count, bytes)
       when is_binary(chunk) and byte_size(chunk) > 0 and count < bounds.archive_chunks and
              bytes + byte_size(chunk) <= bounds.archive_bytes,
       do: validate_chunks(rest, bounds, count + 1, bytes + byte_size(chunk))

  defp validate_chunks(_chunks, _bounds, _count, _bytes), do: {:error, :invalid}

  defp validate_expected_export(expected, bounds) do
    chain = expected.chain
    start_anchor = expected.start_anchor
    end_anchor = expected.end_anchor

    with true <- match?(%ExpectedChain{}, chain),
         true <- match?(%ExpectedAnchor{}, start_anchor),
         true <- match?(%ExpectedAnchor{}, end_anchor),
         {:ok, ^bounds} <- Bounds.coerce(chain.bounds),
         {:ok, ^bounds} <- Bounds.coerce(start_anchor.bounds),
         {:ok, ^bounds} <- Bounds.coerce(end_anchor.bounds),
         :ok <- ContextValidation.expected_chain(chain, bounds),
         :ok <- ContextValidation.expected_anchor(start_anchor, bounds),
         :ok <- ContextValidation.expected_anchor(end_anchor, bounds),
         {:ok, transition_count} <-
           validate_expected_transitions(expected.transitions, bounds, 0),
         true <- transition_count <= bounds.key_transitions,
         true <- transitions_match_chain?(expected.transitions, chain.chain_id),
         true <- start_anchor.chain_id == chain.chain_id,
         true <- end_anchor.chain_id == chain.chain_id,
         true <- start_anchor.sequence == chain.first_sequence - 1,
         true <-
           FixedBytes.equal?(
             start_anchor.chain_hash,
             chain.previous_hash
           ),
         true <- end_anchor.sequence == chain.last_sequence,
         true <- FixedBytes.equal?(end_anchor.chain_hash, chain.last_hash) do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_expected_anchored_export(expected, bounds) do
    export = %ExpectedExport{
      chain: expected.chain,
      start_anchor: expected.start_anchor,
      transitions: expected.transitions,
      end_anchor: expected.end_anchor,
      bounds: bounds
    }

    with :ok <- validate_expected_export(export, bounds),
         true <- is_binary(expected.digest),
         true <- byte_size(expected.digest) == bounds.digest_bytes do
      :ok
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_expected_transitions([], _bounds, count), do: {:ok, count}

  defp validate_expected_transitions(
         [%ExpectedKeyTransition{} = transition | rest],
         bounds,
         count
       )
       when count < bounds.key_transitions do
    case {Bounds.coerce(transition.bounds),
          ContextValidation.expected_transition(transition, bounds)} do
      {{:ok, ^bounds}, :ok} -> validate_expected_transitions(rest, bounds, count + 1)
      _failure -> {:error, :invalid}
    end
  end

  defp validate_expected_transitions(_transitions, _bounds, _count),
    do: {:error, :invalid}

  defp validate_historical_key_shapes([], expected_count, _bounds, expected_count), do: :ok

  defp validate_historical_key_shapes(
         [%HistoricalPublicKey{} = key | rest],
         expected_count,
         bounds,
         count
       )
       when count < expected_count do
    if ContextValidation.historical_key(key, bounds) == :ok do
      validate_historical_key_shapes(rest, expected_count, bounds, count + 1)
    else
      {:error, :invalid}
    end
  end

  defp validate_historical_key_shapes(_keys, _expected_count, _bounds, _count),
    do: {:error, :invalid}

  defp transitions_match_chain?([], _chain_id), do: true

  defp transitions_match_chain?(
         [%ExpectedKeyTransition{chain_id: chain_id} | rest],
         chain_id
       ),
       do: transitions_match_chain?(rest, chain_id)

  defp transitions_match_chain?(_transitions, _chain_id), do: false

  defp parse_expected_transitions([], [], _bounds, _count, accumulator),
    do: {:ok, reverse(accumulator)}

  defp parse_expected_transitions(
         [compact | rest],
         [%ExpectedKeyTransition{} = expected | expected_rest],
         bounds,
         count,
         accumulator
       )
       when is_binary(compact) and count < bounds.key_transitions do
    with {:ok, parsed} <- KeyTransitionCodec.parse(compact, bounds),
         true <- transition_matches?(parsed, expected) do
      parse_expected_transitions(
        rest,
        expected_rest,
        bounds,
        count + 1,
        [parsed | accumulator]
      )
    else
      _failure -> {:error, :invalid}
    end
  end

  defp parse_expected_transitions(_compacts, _expected, _bounds, _count, _accumulator),
    do: {:error, :invalid}

  defp compare_parsed_transitions([], [], accumulator), do: {:ok, reverse(accumulator)}

  defp compare_parsed_transitions(
         [parsed | rest],
         [%ExpectedKeyTransition{} = expected | expected_rest],
         accumulator
       ) do
    if transition_matches?(parsed, expected) do
      compare_parsed_transitions(rest, expected_rest, [parsed | accumulator])
    else
      {:error, :invalid}
    end
  end

  defp anchor_matches?(parsed, expected) do
    parsed.anchor_id == expected.anchor_id and parsed.anchored_at == expected.anchored_at and
      parsed.chain_id == expected.chain_id and parsed.sequence == expected.sequence and
      parsed.key_id == expected.key_id and
      FixedBytes.equal?(parsed.chain_hash, expected.chain_hash) and
      FixedBytes.equal?(parsed.key_fingerprint, expected.key_fingerprint)
  end

  defp transition_matches?(parsed, expected) do
    parsed.transition_id == expected.transition_id and parsed.chain_id == expected.chain_id and
      parsed.effective_at == expected.effective_at and
      current_key_matches?(
        parsed.current_key_id,
        parsed.current_key_fingerprint,
        expected.current_key_id,
        expected.current_key_fingerprint
      ) and
      parsed.next_key_id == expected.next_key_id and
      FixedBytes.equal?(parsed.next_key_fingerprint, expected.next_key_fingerprint)
  end

  defp validate_expected_key_path(start_anchor, [], end_anchor) do
    if start_anchor.key_id == end_anchor.key_id and
         FixedBytes.equal?(start_anchor.key_fingerprint, end_anchor.key_fingerprint) and
         chronological_end?(end_anchor.anchored_at, start_anchor.anchored_at) do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp validate_expected_key_path(start_anchor, transitions, end_anchor) do
    validate_expected_key_path(
      transitions,
      start_anchor.key_id,
      start_anchor.key_fingerprint,
      start_anchor.anchored_at,
      end_anchor,
      [start_anchor.key_fingerprint]
    )
  end

  defp validate_expected_key_path(
         [],
         current_key_id,
         current_fingerprint,
         previous_time,
         end_anchor,
         _seen
       ) do
    if current_key_id == end_anchor.key_id and
         FixedBytes.equal?(current_fingerprint, end_anchor.key_fingerprint) and
         chronological_end?(end_anchor.anchored_at, previous_time) do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp validate_expected_key_path(
         [%ExpectedKeyTransition{} = transition | rest],
         current_key_id,
         current_fingerprint,
         previous_time,
         end_anchor,
         seen
       ) do
    with true <-
           current_key_matches?(
             transition.current_key_id,
             transition.current_key_fingerprint,
             current_key_id,
             current_fingerprint
           ),
         true <- strictly_after?(transition.effective_at, previous_time),
         false <- fingerprint_member?(transition.next_key_fingerprint, seen) do
      validate_expected_key_path(
        rest,
        transition.next_key_id,
        transition.next_key_fingerprint,
        transition.effective_at,
        end_anchor,
        [transition.next_key_fingerprint | seen]
      )
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_key_chain(
         [%HistoricalPublicKey{} = key | rest],
         expected_count,
         bounds,
         seen,
         count
       )
       when count < expected_count do
    with true <- is_binary(key.public_key),
         true <- byte_size(key.public_key) == bounds.public_key_bytes,
         {:ok, fingerprint} <- Jwk.public_key_thumbprint_raw(key.public_key, bounds),
         false <- fingerprint_member?(fingerprint, seen) do
      validate_key_chain_tail(
        rest,
        expected_count,
        bounds,
        [fingerprint | seen],
        count + 1
      )
    else
      _failure -> {:error, :invalid}
    end
  end

  defp validate_key_chain_tail([], expected_count, _bounds, _seen, expected_count), do: :ok

  defp validate_key_chain_tail(keys, expected_count, bounds, seen, count),
    do: validate_key_chain(keys, expected_count, bounds, seen, count)

  defp take_first_key([%HistoricalPublicKey{} = first | rest]), do: {:ok, first, rest}

  defp verify_transitions(
         [],
         [],
         current_key,
         [],
         _bounds,
         previous_time,
         count
       ),
       do: {:ok, current_key, previous_time, count}

  defp verify_transitions(
         [compact | compact_rest],
         [%HistoricalPublicKey{} = next_key | key_rest],
         current_key,
         [%ExpectedKeyTransition{} = expected | expected_rest],
         bounds,
         previous_time,
         count
       ) do
    with true <- strictly_after?(expected.effective_at, previous_time),
         {:ok, facts} <-
           KeyTransitionCodec.verify(
             compact,
             current_key,
             next_key,
             %{expected | bounds: bounds}
           ) do
      verify_transitions(
        compact_rest,
        key_rest,
        next_key,
        expected_rest,
        bounds,
        facts.effective_at,
        count + 1
      )
    else
      _failure -> {:error, :invalid}
    end
  end

  defp authenticated_boundaries?(start_facts, end_facts, chain) do
    start_facts.chain_id == chain.chain_id and end_facts.chain_id == chain.chain_id and
      start_facts.sequence == chain.first_sequence - 1 and
      FixedBytes.equal?(start_facts.chain_hash, chain.previous_hash) and
      end_facts.sequence == chain.last_sequence and
      FixedBytes.equal?(end_facts.chain_hash, chain.last_hash)
  end

  defp header_matches?(header, chain, transitions) do
    header.chain_id == chain.chain_id and header.first_sequence == chain.first_sequence and
      header.last_sequence == chain.last_sequence and header.row_count == chain.row_count and
      header.transition_count == proper_length(transitions, 0) and
      FixedBytes.equal?(header.previous_hash, chain.previous_hash) and
      FixedBytes.equal?(header.last_hash, chain.last_hash)
  end

  defp proper_length([], count), do: count
  defp proper_length([_value | rest], count), do: proper_length(rest, count + 1)

  defp validate_object_versions(observed, expected, bounds) do
    if is_binary(observed) and byte_size(observed) > 0 and
         byte_size(observed) <= bounds.object_version_bytes and is_binary(expected) and
         byte_size(expected) > 0 and byte_size(expected) <= bounds.object_version_bytes and
         observed == expected do
      :ok
    else
      {:error, :invalid}
    end
  end

  defp build_chunks(header, start_anchor, transitions, rows, end_anchor, _bounds) do
    {:ok,
     [@prefix, frame(header), frame(start_anchor)] ++
       frames(transitions, []) ++ frames(rows, []) ++ [frame(end_anchor)]}
  end

  defp frames([], accumulator), do: reverse(accumulator)

  defp frames([value | rest], accumulator),
    do: frames(rest, [frame(value) | accumulator])

  defp frame(bytes),
    do: <<byte_size(bytes)::unsigned-big-integer-size(32), bytes::binary>>

  defp header_json(chain, transitions) do
    {:object,
     [
       {"chain_id", {:string, chain.chain_id}},
       {"first_sequence", {:integer, chain.first_sequence}},
       {"last_hash", {:string, Base.url_encode64(chain.last_hash, padding: false)}},
       {"last_sequence", {:integer, chain.last_sequence}},
       {"previous_hash", {:string, Base.url_encode64(chain.previous_hash, padding: false)}},
       {"row_count", {:integer, chain.row_count}},
       {"transition_count", {:integer, proper_length(transitions, 0)}},
       {"v", {:integer, 1}}
     ]}
  end

  defp hash_chunks(chunks) do
    context = :crypto.hash_init(:sha256)
    context = hash_chunks(chunks, context)
    :crypto.hash_final(context)
  end

  defp hash_chunks([], context), do: context

  defp hash_chunks([chunk | rest], context),
    do: hash_chunks(rest, :crypto.hash_update(context, chunk))

  defp fingerprint_member?(_fingerprint, []), do: false

  defp fingerprint_member?(fingerprint, [candidate | rest]) do
    FixedBytes.equal?(fingerprint, candidate) or fingerprint_member?(fingerprint, rest)
  end

  defp strictly_after?(value, previous), do: value > previous
  defp chronological_end?(value, previous), do: value >= previous

  defp current_key_matches?(left_id, left_fingerprint, right_id, right_fingerprint),
    do: left_id == right_id and FixedBytes.equal?(left_fingerprint, right_fingerprint)

  defp reverse(values), do: reverse(values, [])
  defp reverse([], accumulator), do: accumulator
  defp reverse([value | rest], accumulator), do: reverse(rest, [value | accumulator])

  defp closed_map(members, keys) when is_list(members) do
    if length(members) == length(keys) and
         Enum.sort(Enum.map(members, &elem(&1, 0))) == Enum.sort(keys) do
      {:ok, Map.new(members)}
    else
      {:error, :invalid}
    end
  end
end
