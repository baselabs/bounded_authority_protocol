defmodule BoundedAuthorityProtocol.V2.AnchoredExportTest do
  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.V1
  alias BoundedAuthorityProtocol.V1.AnchoredExportInput
  alias BoundedAuthorityProtocol.V1.ArchivedObject
  alias BoundedAuthorityProtocol.V1.BoundaryAnchor
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
  alias BoundedAuthorityProtocol.V2
  alias BoundedAuthorityProtocol.V2.AnchoredExportCodec
  alias BoundedAuthorityProtocol.V2.AnchoredExportFacts

  @zero_hash <<0::256>>
  # The v2 archive prefix is byte-distinct from the v1 BAP1 prefix at frame offset 0.
  @archive_prefix "BAP2-ARCHIVE\0EXPORT\0"

  test "atomically verifies a chunk-split v2 export across an authenticated key rollover" do
    context = rollover_context()

    assert {:ok, encoded} = V2.encode_anchored_export(context.input, context.expected_export)

    assert Enum.at(encoded.chunks, 0) == @archive_prefix
    assert encoded.byte_count == encoded.chunks |> IO.iodata_length()
    assert encoded.digest == :crypto.hash(:sha256, encoded.chunks)

    chunks =
      encoded.chunks
      |> IO.iodata_to_binary()
      |> :binary.bin_to_list()
      |> one_byte_chunks()

    archived = %ArchivedObject{chunks: chunks, version: "object-version-7"}

    expected = %ExpectedAnchoredExport{
      chain: context.chain,
      start_anchor: context.start_expected,
      transitions: [context.transition_expected],
      end_anchor: context.end_expected,
      digest: encoded.digest,
      object_version: "object-version-7",
      bounds: %{}
    }

    start_fingerprint = context.start_expected.key_fingerprint
    end_fingerprint = context.end_expected.key_fingerprint
    expected_last_hash = context.chain.last_hash
    expected_digest = encoded.digest

    assert {:ok,
            %AnchoredExportFacts{
              version: 2,
              chain_id: "urn:example:chain",
              first_sequence: 1,
              last_sequence: 2,
              row_count: 2,
              previous_hash: @zero_hash,
              last_hash: ^expected_last_hash,
              digest: ^expected_digest,
              start_anchor_id: "urn:example:anchor:start",
              start_anchored_at: 1999,
              start_key_fingerprint: ^start_fingerprint,
              end_anchor_id: "urn:example:anchor:end",
              end_anchored_at: 2001,
              end_key_fingerprint: ^end_fingerprint,
              transition_count: 1,
              verification: :anchored_export,
              trust: :not_evaluated,
              authorization: :not_evaluated
            } = facts} =
             V2.verify_anchored_export(archived, context.key_chain, expected)

    assert inspect(facts) == "#BoundedAuthorityProtocol.V2.AnchoredExportFacts<redacted>"
  end

  test "a v1-encoded export with matching context is rejected by v2 verification" do
    context = legacy_major_rollover_context()

    assert {:ok, legacy_encoded} =
             V1.encode_anchored_export(context.input, context.expected_export)

    refute Enum.at(legacy_encoded.chunks, 0) == @archive_prefix

    expected = %ExpectedAnchoredExport{
      chain: context.chain,
      start_anchor: context.start_expected,
      transitions: [context.transition_expected],
      end_anchor: context.end_expected,
      digest: legacy_encoded.digest,
      object_version: "object-version-7",
      bounds: %{}
    }

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %ArchivedObject{chunks: legacy_encoded.chunks, version: "object-version-7"},
               context.key_chain,
               expected
             )
  end

  test "rejects digest/version/EOF/frame/transition/coverage drift and non-raw evidence" do
    context = rollover_context()
    {:ok, encoded} = V2.encode_anchored_export(context.input, context.expected_export)

    expected = %ExpectedAnchoredExport{
      chain: context.chain,
      start_anchor: context.start_expected,
      transitions: [context.transition_expected],
      end_anchor: context.end_expected,
      digest: encoded.digest,
      object_version: "object-version-7",
      bounds: %{}
    }

    archived = %ArchivedObject{chunks: encoded.chunks, version: "object-version-7"}

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               context.key_chain,
               %{expected | digest: <<0::256>>}
             )

    # A structurally malformed digest fails expected-context validation itself.
    assert {:error, :invalid} =
             V2.verify_anchored_export(archived, context.key_chain, %{expected | digest: <<0>>})

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %{archived | version: "object-version-8"},
               context.key_chain,
               expected
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %{archived | chunks: encoded.chunks ++ [<<0>>]},
               context.key_chain,
               %{expected | digest: :crypto.hash(:sha256, encoded.chunks ++ [<<0>>])}
             )

    # A zero-length frame header inside the archive fails frame reading.
    malformed_row_chunks = List.replace_at(encoded.chunks, 4, <<0::32>>)

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %{archived | chunks: malformed_row_chunks},
               context.key_chain,
               %{expected | digest: :crypto.hash(:sha256, malformed_row_chunks)}
             )

    # A non-canonical header object fails header parsing even with a fresh digest.
    malformed_header_chunks = List.replace_at(encoded.chunks, 1, <<2::32, "{}"::binary>>)

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %{archived | chunks: malformed_header_chunks},
               context.key_chain,
               %{expected | digest: :crypto.hash(:sha256, malformed_header_chunks)}
             )

    # Expected transition drift is caught against the parsed archive transitions.
    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               context.key_chain,
               %{
                 expected
                 | transitions: [%{context.transition_expected | effective_at: 2001}]
               }
             )

    # A key window that excludes the transition time fails the rollover walk.
    [start_key, end_key] = context.key_chain.keys

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               %HistoricalKeyChain{keys: [%{start_key | valid_before: 2000}, end_key]},
               expected
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               %HistoricalKeyChain{keys: tl(context.key_chain.keys)},
               expected
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               %HistoricalKeyChain{keys: [:invalid]},
               expected
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               %HistoricalKeyChain{keys: [%{start_key | key_id: "bad key"} | [end_key]]},
               expected
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               context.key_chain,
               %{expected | chain: %{context.chain | chain_id: "x:%zz"}}
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               context.key_chain,
               %{
                 expected
                 | transitions: [
                     %{
                       context.transition_expected
                       | effective_at: 9_007_199_254_740_992
                     }
                   ]
               }
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               context.key_chain,
               %{expected | start_anchor: %{context.start_expected | anchored_at: 1998}}
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               archived,
               context.key_chain,
               %{expected | chain: %{context.chain | row_count: 1}}
             )

    assert {:error, :invalid} = V2.verify_anchored_export(encoded, context.key_chain, expected)

    {:ok, facts} = V2.check_chain(%ChainInput{rows: context.input.rows}, context.chain)

    assert {:error, :invalid} = V2.verify_anchored_export(facts, context.key_chain, expected)

    assert {:error, :invalid} = AnchoredExportCodec.encode(%{}, %{})
    assert {:error, :invalid} = AnchoredExportCodec.verify(%{}, %{}, %{})

    assert {:error, :invalid} =
             AnchoredExportCodec.verify(encoded, context.key_chain, expected)

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %ArchivedObject{chunks: [], version: "object-version-7"},
               context.key_chain,
               expected
             )

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %ArchivedObject{chunks: [<<>>], version: "object-version-7"},
               context.key_chain,
               expected
             )

    truncated =
      encoded.chunks
      |> IO.iodata_to_binary()
      |> binary_part(0, encoded.byte_count - 1)

    assert {:error, :invalid} =
             V2.verify_anchored_export(
               %ArchivedObject{chunks: [truncated], version: "object-version-7"},
               context.key_chain,
               %{expected | digest: :crypto.hash(:sha256, truncated)}
             )

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               context.input,
               %{context.expected_export | transitions: :invalid}
             )

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               context.input,
               %{
                 context.expected_export
                 | transitions: [%{context.transition_expected | bounds: %{chain_rows: 1}}]
               }
             )

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               context.input,
               %{
                 context.expected_export
                 | transitions: [
                     %{context.transition_expected | transition_id: "urn:example:transition:x"}
                   ]
               }
             )

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               %{context.input | transitions: []},
               context.expected_export
             )
  end

  test "same-key boundaries require no transition and permit equal anchor times" do
    {public_key, private_key} = ed25519_keypair(<<6::256>>)
    {:ok, fingerprint} = Jwk.public_key_thumbprint_raw(public_key, %{})
    {rows, chain} = rows_and_chain()

    start_anchor =
      anchor("urn:example:anchor:start", 2000, 0, @zero_hash, "archive-key-a", public_key)

    end_anchor =
      anchor(
        "urn:example:anchor:end",
        2000,
        chain.last_sequence,
        chain.last_hash,
        "archive-key-a",
        public_key
      )

    start_compact = sign_anchor(start_anchor, private_key)
    end_compact = sign_anchor(end_anchor, private_key)
    start_expected = expected_anchor(start_anchor, fingerprint)
    end_expected = expected_anchor(end_anchor, fingerprint)

    input = %AnchoredExportInput{
      rows: rows,
      start_anchor: start_compact,
      transitions: [],
      end_anchor: end_compact
    }

    export_expected = %ExpectedExport{
      chain: chain,
      start_anchor: start_expected,
      transitions: [],
      end_anchor: end_expected,
      bounds: %{}
    }

    assert {:ok, encoded} = V2.encode_anchored_export(input, export_expected)

    expected = %ExpectedAnchoredExport{
      chain: chain,
      start_anchor: start_expected,
      transitions: [],
      end_anchor: end_expected,
      digest: encoded.digest,
      object_version: "v2",
      bounds: %{}
    }

    key_chain = %HistoricalKeyChain{
      keys: [
        %HistoricalPublicKey{
          key_id: "archive-key-a",
          public_key: public_key,
          valid_from: 1000,
          valid_before: :unbounded
        }
      ]
    }

    assert {:ok, %AnchoredExportFacts{version: 2, transition_count: 0}} =
             V2.verify_anchored_export(
               %ArchivedObject{chunks: encoded.chunks, version: "v2"},
               key_chain,
               expected
             )
  end

  test "key rollover may retain its key ID and end exactly at transition time" do
    context = rollover_context()

    transition = %{
      context.transition
      | next_key_id: context.transition.current_key_id
    }

    end_anchor = %{
      context.end_anchor
      | anchored_at: transition.effective_at,
        key_id: transition.current_key_id
    }

    next_fingerprint = context.transition_expected.next_key_fingerprint

    transition_expected = %{
      context.transition_expected
      | next_key_id: transition.current_key_id
    }

    end_expected = %{
      context.end_expected
      | anchored_at: transition.effective_at,
        key_id: transition.current_key_id
    }

    input = %{
      context.input
      | transitions: [sign_transition(transition, context.current_private)],
        end_anchor: sign_anchor(end_anchor, context.next_private)
    }

    export_expected = %{
      context.expected_export
      | transitions: [transition_expected],
        end_anchor: end_expected
    }

    key_chain = %HistoricalKeyChain{
      keys: [
        hd(context.key_chain.keys),
        %{
          List.last(context.key_chain.keys)
          | key_id: transition.current_key_id
        }
      ]
    }

    assert {:ok, encoded} = V2.encode_anchored_export(input, export_expected)

    expected = %ExpectedAnchoredExport{
      chain: context.chain,
      start_anchor: context.start_expected,
      transitions: [transition_expected],
      end_anchor: end_expected,
      digest: encoded.digest,
      object_version: "same-id-equal-time",
      bounds: %{}
    }

    assert {:ok,
            %AnchoredExportFacts{
              version: 2,
              end_anchored_at: 2000,
              end_key_fingerprint: ^next_fingerprint
            }} =
             V2.verify_anchored_export(
               %ArchivedObject{chunks: encoded.chunks, version: "same-id-equal-time"},
               key_chain,
               expected
             )
  end

  test "rejects a correctly signed transition for another chain" do
    context = rollover_context()

    transition = %{
      context.transition
      | chain_id: "urn:example:other-chain"
    }

    transition_expected = %{
      context.transition_expected
      | chain_id: transition.chain_id
    }

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               %{
                 context.input
                 | transitions: [sign_transition(transition, context.current_private)]
               },
               %{
                 context.expected_export
                 | transitions: [transition_expected]
               }
             )
  end

  test "rejects correctly signed anchors outside the caller's exact boundaries" do
    context = rollover_context()

    shifted_start = %{context.start_anchor | sequence: 1}

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               %{
                 context.input
                 | start_anchor: sign_anchor(shifted_start, context.current_private)
               },
               %{
                 context.expected_export
                 | start_anchor: %{context.start_expected | sequence: shifted_start.sequence}
               }
             )

    shifted_end = %{context.end_anchor | sequence: context.chain.last_sequence - 1}

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               %{
                 context.input
                 | end_anchor: sign_anchor(shifted_end, context.next_private)
               },
               %{
                 context.expected_export
                 | end_anchor: %{context.end_expected | sequence: shifted_end.sequence}
               }
             )
  end

  test "rejects non-increasing transition order and broken expected-key continuity" do
    context = rollover_context()
    late_start = %{context.start_anchor | anchored_at: context.transition.effective_at}

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               %{
                 context.input
                 | start_anchor: sign_anchor(late_start, context.current_private)
               },
               %{
                 context.expected_export
                 | start_anchor: %{context.start_expected | anchored_at: late_start.anchored_at}
               }
             )

    {unrelated_public, _unrelated_private} = ed25519_keypair(<<7::256>>)
    {:ok, unrelated_fingerprint} = Jwk.public_key_thumbprint_raw(unrelated_public, %{})

    broken_transition = %{
      context.transition_expected
      | current_key_id: "archive-key-unrelated",
        current_key_fingerprint: unrelated_fingerprint
    }

    assert {:error, :invalid} =
             V2.encode_anchored_export(
               context.input,
               %{context.expected_export | transitions: [broken_transition]}
             )
  end

  defp rollover_context do
    {current_public, current_private} = ed25519_keypair(<<4::256>>)
    {next_public, next_private} = ed25519_keypair(<<5::256>>)
    {:ok, current_fingerprint} = Jwk.public_key_thumbprint_raw(current_public, %{})
    {:ok, next_fingerprint} = Jwk.public_key_thumbprint_raw(next_public, %{})
    {rows, chain} = rows_and_chain()

    start_anchor =
      anchor("urn:example:anchor:start", 1999, 0, @zero_hash, "archive-key-a", current_public)

    end_anchor =
      anchor(
        "urn:example:anchor:end",
        2001,
        chain.last_sequence,
        chain.last_hash,
        "archive-key-b",
        next_public
      )

    transition = %KeyTransition{
      transition_id: "urn:example:transition:a-b",
      chain_id: chain.chain_id,
      effective_at: 2000,
      current_key_id: "archive-key-a",
      current_public_key: current_public,
      next_key_id: "archive-key-b",
      next_public_key: next_public
    }

    start_expected = expected_anchor(start_anchor, current_fingerprint)
    end_expected = expected_anchor(end_anchor, next_fingerprint)

    transition_expected = %ExpectedKeyTransition{
      transition_id: transition.transition_id,
      chain_id: transition.chain_id,
      effective_at: transition.effective_at,
      current_key_id: transition.current_key_id,
      current_key_fingerprint: current_fingerprint,
      next_key_id: transition.next_key_id,
      next_key_fingerprint: next_fingerprint,
      bounds: %{}
    }

    input = %AnchoredExportInput{
      rows: rows,
      start_anchor: sign_anchor(start_anchor, current_private),
      transitions: [sign_transition(transition, current_private)],
      end_anchor: sign_anchor(end_anchor, next_private)
    }

    expected_export = %ExpectedExport{
      chain: chain,
      start_anchor: start_expected,
      transitions: [transition_expected],
      end_anchor: end_expected,
      bounds: %{}
    }

    key_chain = %HistoricalKeyChain{
      keys: [
        %HistoricalPublicKey{
          key_id: "archive-key-a",
          public_key: current_public,
          valid_from: 1000,
          valid_before: 3000
        },
        %HistoricalPublicKey{
          key_id: "archive-key-b",
          public_key: next_public,
          valid_from: 1500,
          valid_before: :unbounded
        }
      ]
    }

    %{
      input: input,
      expected_export: expected_export,
      chain: chain,
      start_anchor: start_anchor,
      transition: transition,
      end_anchor: end_anchor,
      start_expected: start_expected,
      transition_expected: transition_expected,
      end_expected: end_expected,
      key_chain: key_chain,
      current_private: current_private,
      next_private: next_private
    }
  end

  # A byte-identical v1 rollover: the same seeded keys and boundaries, produced
  # and verified by the v1 facade so the cross-major rejection is attributable
  # to the v2 archive prefix and version claims alone.
  defp legacy_major_rollover_context do
    {current_public, current_private} = ed25519_keypair(<<4::256>>)
    {next_public, next_private} = ed25519_keypair(<<5::256>>)
    {:ok, current_fingerprint} = Jwk.public_key_thumbprint_raw(current_public, %{})
    {:ok, next_fingerprint} = Jwk.public_key_thumbprint_raw(next_public, %{})

    first_entry = %ConsumptionEntry{
      chain_id: "urn:example:chain",
      sequence: 1,
      previous_hash: @zero_hash,
      commitment: :crypto.hash(:sha256, "commitment-a")
    }

    {:ok, first} = V1.encode_consumption_entry(first_entry, %{})

    second_entry = %ConsumptionEntry{
      chain_id: "urn:example:chain",
      sequence: 2,
      previous_hash: first.hash,
      commitment: :crypto.hash(:sha256, "commitment-b")
    }

    {:ok, second} = V1.encode_consumption_entry(second_entry, %{})

    chain = %ExpectedChain{
      chain_id: "urn:example:chain",
      first_sequence: 1,
      last_sequence: 2,
      row_count: 2,
      previous_hash: @zero_hash,
      last_hash: second.hash,
      bounds: %{}
    }

    start_anchor =
      anchor("urn:example:anchor:start", 1999, 0, @zero_hash, "archive-key-a", current_public)

    end_anchor =
      anchor(
        "urn:example:anchor:end",
        2001,
        chain.last_sequence,
        chain.last_hash,
        "archive-key-b",
        next_public
      )

    transition = %KeyTransition{
      transition_id: "urn:example:transition:a-b",
      chain_id: chain.chain_id,
      effective_at: 2000,
      current_key_id: "archive-key-a",
      current_public_key: current_public,
      next_key_id: "archive-key-b",
      next_public_key: next_public
    }

    input = %AnchoredExportInput{
      rows: [first.bytes, second.bytes],
      start_anchor: legacy_sign_anchor(start_anchor, current_private),
      transitions: [legacy_sign_transition(transition, current_private)],
      end_anchor: legacy_sign_anchor(end_anchor, next_private)
    }

    expected_export = %ExpectedExport{
      chain: chain,
      start_anchor: expected_anchor(start_anchor, current_fingerprint),
      transitions: [
        %ExpectedKeyTransition{
          transition_id: transition.transition_id,
          chain_id: transition.chain_id,
          effective_at: transition.effective_at,
          current_key_id: transition.current_key_id,
          current_key_fingerprint: current_fingerprint,
          next_key_id: transition.next_key_id,
          next_key_fingerprint: next_fingerprint,
          bounds: %{}
        }
      ],
      end_anchor: expected_anchor(end_anchor, next_fingerprint),
      bounds: %{}
    }

    key_chain = %HistoricalKeyChain{
      keys: [
        %HistoricalPublicKey{
          key_id: "archive-key-a",
          public_key: current_public,
          valid_from: 1000,
          valid_before: 3000
        },
        %HistoricalPublicKey{
          key_id: "archive-key-b",
          public_key: next_public,
          valid_from: 1500,
          valid_before: :unbounded
        }
      ]
    }

    %{
      input: input,
      expected_export: expected_export,
      chain: chain,
      start_expected: expected_export.start_anchor,
      transition_expected: hd(expected_export.transitions),
      end_expected: expected_export.end_anchor,
      key_chain: key_chain
    }
  end

  defp rows_and_chain do
    first_entry = %ConsumptionEntry{
      chain_id: "urn:example:chain",
      sequence: 1,
      previous_hash: @zero_hash,
      commitment: :crypto.hash(:sha256, "commitment-a")
    }

    {:ok, first} = V2.encode_consumption_entry(first_entry, %{})

    second_entry = %ConsumptionEntry{
      chain_id: "urn:example:chain",
      sequence: 2,
      previous_hash: first.hash,
      commitment: :crypto.hash(:sha256, "commitment-b")
    }

    {:ok, second} = V2.encode_consumption_entry(second_entry, %{})

    chain = %ExpectedChain{
      chain_id: "urn:example:chain",
      first_sequence: 1,
      last_sequence: 2,
      row_count: 2,
      previous_hash: @zero_hash,
      last_hash: second.hash,
      bounds: %{}
    }

    {[first.bytes, second.bytes], chain}
  end

  defp ed25519_keypair(seed) do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519, seed)
    {public_key, private_key}
  end

  defp anchor(anchor_id, anchored_at, sequence, chain_hash, key_id, public_key) do
    %BoundaryAnchor{
      anchor_id: anchor_id,
      anchored_at: anchored_at,
      chain_id: "urn:example:chain",
      sequence: sequence,
      chain_hash: chain_hash,
      key_id: key_id,
      public_key: public_key
    }
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
      bounds: %{}
    }
  end

  defp sign_anchor(anchor, private_key) do
    {:ok, input} = V2.boundary_anchor_signing_input(anchor, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [private_key, :ed25519])
    {:ok, compact} = V2.assemble_compact(input, signature)
    compact
  end

  defp sign_transition(transition, private_key) do
    {:ok, input} = V2.key_transition_signing_input(transition, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [private_key, :ed25519])
    {:ok, compact} = V2.assemble_compact(input, signature)
    compact
  end

  defp legacy_sign_anchor(anchor, private_key) do
    {:ok, input} = V1.boundary_anchor_signing_input(anchor, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [private_key, :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    compact
  end

  defp legacy_sign_transition(transition, private_key) do
    {:ok, input} = V1.key_transition_signing_input(transition, %{})
    signature = :crypto.sign(:eddsa, :none, input.message, [private_key, :ed25519])
    {:ok, compact} = V1.assemble_compact(input, signature)
    compact
  end

  defp one_byte_chunks(bytes), do: one_byte_chunks(bytes, [])
  defp one_byte_chunks([], accumulator), do: Enum.reverse(accumulator)

  defp one_byte_chunks([byte | rest], accumulator),
    do: one_byte_chunks(rest, [<<byte>> | accumulator])
end
