alias BoundedAuthorityProtocol.V1
alias BoundedAuthorityProtocol.V1.AnchoredExportInput
alias BoundedAuthorityProtocol.V1.ArchivedObject
alias BoundedAuthorityProtocol.V1.BoundaryAnchor
alias BoundedAuthorityProtocol.V1.Bounds
alias BoundedAuthorityProtocol.V1.ChainInput
alias BoundedAuthorityProtocol.V1.ConsumptionEntry
alias BoundedAuthorityProtocol.V1.ExpectedAnchor
alias BoundedAuthorityProtocol.V1.ExpectedAnchoredExport
alias BoundedAuthorityProtocol.V1.ExpectedChain
alias BoundedAuthorityProtocol.V1.ExpectedExport
alias BoundedAuthorityProtocol.V1.ExpectedKeyTransition
alias BoundedAuthorityProtocol.V1.HistoricalKeyChain
alias BoundedAuthorityProtocol.V1.HistoricalPublicKey
alias BoundedAuthorityProtocol.V1.Jwk
alias BoundedAuthorityProtocol.V1.KeyTransition

defmodule BoundedAuthorityProtocol.ChainArchivePerformanceGate do
  @iterations 20
  @maximum_wall_microseconds 60_000_000
  @sample_timeout_milliseconds div(@maximum_wall_microseconds, 1_000) + 5_000
  @maximum_reductions 2_000_000_000
  @maximum_heap_growth_bytes 536_870_912
  @maximum_count_archive_bytes 45_188_751
  @chain_id "urn:" <> String.duplicate("a", 508)
  @anchor_id "urn:" <> String.duplicate("n", 508)
  @time_base 9_007_199_254_740_700

  def run do
    bounds = Bounds.maximum()
    assert!(bounds.chain_rows == 65_536, "chain-row maximum drift")
    assert!(bounds.key_transitions == 256, "transition maximum drift")
    assert!(bounds.archive_chunks == 65_796, "archive-chunk maximum drift")
    assert!(bounds.archive_bytes == 270_820_384, "archive-byte maximum drift")

    {rows, chain} = maximum_chain(bounds.chain_rows)
    {input, expected_export, key_chain, start_anchor, start_key} = maximum_key_path(rows, chain)
    {:ok, encoded} = V1.encode_anchored_export(input, expected_export)

    assert!(length(encoded.chunks) == bounds.archive_chunks, "maximum-valid chunk count")

    assert!(
      encoded.byte_count == @maximum_count_archive_bytes,
      "maximum-count archive byte size expected=#{@maximum_count_archive_bytes} " <>
        "actual=#{encoded.byte_count}"
    )

    assert!(encoded.byte_count <= bounds.archive_bytes, "archive envelope bound")

    IO.puts(
      "maximum-count archive built: rows=#{length(rows)} " <>
        "transitions=#{length(input.transitions)} chunks=#{length(encoded.chunks)} " <>
        "archive_bytes=#{encoded.byte_count} envelope_bytes=#{bounds.archive_bytes}"
    )

    expected = %ExpectedAnchoredExport{
      chain: chain,
      start_anchor: expected_export.start_anchor,
      transitions: expected_export.transitions,
      end_anchor: expected_export.end_anchor,
      digest: encoded.digest,
      object_version: String.duplicate("v", bounds.object_version_bytes),
      bounds: bounds
    }

    archived = %ArchivedObject{
      chunks: encoded.chunks,
      version: expected.object_version
    }

    measurements = [
      measure("maximum chain", fn ->
        {:ok, _facts} = V1.check_chain(%ChainInput{rows: rows}, chain)
      end),
      measure("historical anchor", fn ->
        {:ok, _facts} =
          V1.verify_historical_anchor(input.start_anchor, start_key, start_anchor)
      end),
      measure("maximum anchored export", fn ->
        {:ok, _facts} = V1.verify_anchored_export(archived, key_chain, expected)
      end),
      measure("maximum-plus-one malformed archive", fn ->
        oversized_chunk = :binary.copy(<<0>>, bounds.archive_header_bytes)
        count = div(bounds.archive_bytes, byte_size(oversized_chunk)) + 1
        chunks = List.duplicate(oversized_chunk, count)

        {:error, :invalid} =
          V1.verify_anchored_export(%{archived | chunks: chunks}, key_chain, expected)
      end)
    ]

    Enum.each(measurements, fn result ->
      IO.puts(
        "#{result.name}: iterations=#{@iterations} " <>
          "worst_wall_us=#{result.wall} worst_reductions=#{result.reductions} " <>
          "worst_heap_growth_bytes=#{result.heap}"
      )
    end)

    Enum.each(measurements, &enforce!/1)

    IO.puts(
      "chain_archive performance gate: ok rows=#{length(rows)} transitions=#{length(input.transitions)} " <>
        "chunks=#{length(encoded.chunks)} archive_bytes=#{encoded.byte_count}"
    )
  end

  defp maximum_chain(count) do
    last_sequence = Bounds.maximum().integer_magnitude
    first_sequence = last_sequence - count + 1
    previous_hash = :crypto.hash(:sha256, "maximum-width-continued-range")

    {rows, _hashes, last_hash} =
      Enum.reduce(
        first_sequence..last_sequence,
        {[], [], previous_hash},
        fn sequence, {rows, hashes, previous} ->
          entry = %ConsumptionEntry{
            chain_id: @chain_id,
            sequence: sequence,
            previous_hash: previous,
            commitment: :crypto.hash(:sha256, <<sequence::unsigned-big-integer-size(64)>>)
          }

          {:ok, encoded} = V1.encode_consumption_entry(entry, Bounds.maximum())
          {[encoded.bytes | rows], [encoded.hash | hashes], encoded.hash}
        end
      )

    rows = Enum.reverse(rows)

    chain = %ExpectedChain{
      chain_id: @chain_id,
      first_sequence: first_sequence,
      last_sequence: last_sequence,
      row_count: count,
      previous_hash: previous_hash,
      last_hash: last_hash,
      bounds: Bounds.maximum()
    }

    {rows, chain}
  end

  defp maximum_key_path(rows, chain) do
    keys =
      Enum.map(0..256, fn index ->
        {public, private} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, fingerprint} = Jwk.public_key_thumbprint_raw(public, Bounds.maximum())

        %{
          id: maximum_key_id(index),
          public: public,
          private: private,
          fingerprint: fingerprint
        }
      end)

    start_key = hd(keys)
    end_key = List.last(keys)

    start =
      %BoundaryAnchor{
        anchor_id: @anchor_id,
        anchored_at: @time_base,
        chain_id: chain.chain_id,
        sequence: chain.first_sequence - 1,
        chain_hash: chain.previous_hash,
        key_id: start_key.id,
        public_key: start_key.public
      }

    ending =
      %BoundaryAnchor{
        anchor_id: @anchor_id,
        anchored_at: @time_base + 257,
        chain_id: chain.chain_id,
        sequence: chain.last_sequence,
        chain_hash: chain.last_hash,
        key_id: end_key.id,
        public_key: end_key.public
      }

    transitions =
      keys
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.with_index(1)
      |> Enum.map(fn {[current, next], index} ->
        value = %KeyTransition{
          transition_id: maximum_transition_id(index),
          chain_id: chain.chain_id,
          effective_at: @time_base + index,
          current_key_id: current.id,
          current_public_key: current.public,
          next_key_id: next.id,
          next_public_key: next.public
        }

        %{value: value, current: current, next: next}
      end)

    start_compact = sign_anchor(start, start_key.private)
    end_compact = sign_anchor(ending, end_key.private)

    transition_compacts =
      Enum.map(transitions, &sign_transition(&1.value, &1.current.private))

    start_expected = expected_anchor(start, start_key.fingerprint)
    end_expected = expected_anchor(ending, end_key.fingerprint)

    transition_expected =
      Enum.map(transitions, fn transition ->
        %ExpectedKeyTransition{
          transition_id: transition.value.transition_id,
          chain_id: transition.value.chain_id,
          effective_at: transition.value.effective_at,
          current_key_id: transition.current.id,
          current_key_fingerprint: transition.current.fingerprint,
          next_key_id: transition.next.id,
          next_key_fingerprint: transition.next.fingerprint,
          bounds: Bounds.maximum()
        }
      end)

    input = %AnchoredExportInput{
      rows: rows,
      start_anchor: start_compact,
      transitions: transition_compacts,
      end_anchor: end_compact
    }

    expected_export = %ExpectedExport{
      chain: chain,
      start_anchor: start_expected,
      transitions: transition_expected,
      end_anchor: end_expected,
      bounds: Bounds.maximum()
    }

    key_chain = %HistoricalKeyChain{
      keys:
        Enum.map(keys, fn key ->
          %HistoricalPublicKey{
            key_id: key.id,
            public_key: key.public,
            valid_from: @time_base - 1,
            valid_before: :unbounded
          }
        end)
    }

    {input, expected_export, key_chain, start_expected, hd(key_chain.keys)}
  end

  defp sign_anchor(anchor, private) do
    {:ok, input} = V1.boundary_anchor_signing_input(anchor, Bounds.maximum())
    signature = :crypto.sign(:eddsa, :none, input.message, [private, :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    compact
  end

  defp sign_transition(transition, private) do
    {:ok, input} = V1.key_transition_signing_input(transition, Bounds.maximum())
    signature = :crypto.sign(:eddsa, :none, input.message, [private, :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    compact
  end

  defp expected_anchor(anchor, fingerprint) do
    %ExpectedAnchor{
      anchor_id: anchor.anchor_id,
      anchored_at: anchor.anchored_at,
      chain_id: anchor.chain_id,
      sequence: anchor.sequence,
      chain_hash: anchor.chain_hash,
      key_id: anchor.key_id,
      key_fingerprint: fingerprint,
      bounds: Bounds.maximum()
    }
  end

  defp maximum_key_id(index) do
    suffix = index |> Integer.to_string() |> String.pad_leading(6, "0")
    String.duplicate("k", Bounds.maximum().kid_bytes - byte_size(suffix)) <> suffix
  end

  defp maximum_transition_id(index) do
    suffix = index |> Integer.to_string() |> String.pad_leading(6, "0")

    "urn:" <>
      String.duplicate("t", Bounds.maximum().identifier_bytes - 4 - byte_size(suffix)) <>
      suffix
  end

  defp measure(name, function) do
    samples =
      Enum.map(1..@iterations, fn iteration ->
        IO.puts("#{name}: sample=#{iteration}/#{@iterations}")
        isolated_sample(name, function)
      end)

    %{
      name: name,
      wall: samples |> Enum.map(& &1.wall) |> Enum.max(),
      reductions: samples |> Enum.map(& &1.reductions) |> Enum.max(),
      heap: samples |> Enum.map(& &1.heap) |> Enum.max()
    }
  end

  defp isolated_sample(name, function) do
    parent = self()
    reference = make_ref()

    {pid, monitor} =
      spawn_monitor(fn ->
        :erlang.garbage_collect(self())
        {:reductions, before_reductions} = Process.info(self(), :reductions)
        {:total_heap_size, before_heap} = Process.info(self(), :total_heap_size)
        started = System.monotonic_time()
        function.()
        elapsed = System.monotonic_time() - started
        {:reductions, after_reductions} = Process.info(self(), :reductions)
        {:total_heap_size, after_heap} = Process.info(self(), :total_heap_size)

        sample = %{
          wall: System.convert_time_unit(elapsed, :native, :microsecond),
          reductions: after_reductions - before_reductions,
          heap: max(after_heap - before_heap, 0) * :erlang.system_info(:wordsize)
        }

        send(parent, {reference, self(), sample})

        receive do
          {^reference, :acknowledged} -> :ok
        after
          1_000 -> exit(:sample_acknowledgement_timeout)
        end
      end)

    receive do
      {^reference, ^pid, sample} ->
        send(pid, {reference, :acknowledged})

        receive do
          {:DOWN, ^monitor, :process, ^pid, :normal} ->
            sample

          {:DOWN, ^monitor, :process, ^pid, reason} ->
            raise("#{name} sample failed: #{inspect(reason)}")
        end

      {:DOWN, ^monitor, :process, ^pid, reason} ->
        raise("#{name} sample failed: #{inspect(reason)}")
    after
      @sample_timeout_milliseconds ->
        Process.exit(pid, :kill)

        receive do
          {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
        end

        raise("#{name} sample timeout")
    end
  end

  defp enforce!(result) do
    assert!(result.wall <= @maximum_wall_microseconds, "#{result.name} wall-time bound")
    assert!(result.reductions <= @maximum_reductions, "#{result.name} reductions bound")
    assert!(result.heap <= @maximum_heap_growth_bytes, "#{result.name} heap-growth bound")
  end

  defp assert!(true, _message), do: :ok
  defp assert!(false, message), do: raise(message)
end

BoundedAuthorityProtocol.ChainArchivePerformanceGate.run()
