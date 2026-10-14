defmodule BoundedAuthorityProtocol.Architecture.ProducerCanonicalityScopeTest do
  @moduledoc """
  Erratum 3 adds the keyless signature rules to the producer surfaces only. On contract-majors
  1, 2 and 3, no decode or parse function reaches a producer canonicality check: a decoded
  compact is not a verified one, and decode verdicts on existing profiles do not change.

  The check reads compiled code: from every `decode_*`, `parse_grant*`, `parse_proof*` and
  `parse/2` function of the v1, v2 and v3 contract-major modules it follows local and package
  calls transitively and asserts that none reaches `Ed25519.signature_gate?/1`,
  `V3.Es256.canonical_signature/1`, or `Es256.canonical_signature?/1`.

  The scope is the contract-major MFAs alone: a sibling profile defined later may check
  canonicality at decode by design.
  """

  use ExUnit.Case, async: true

  @helpers MapSet.new([
             {BoundedAuthorityProtocol.Ed25519, :signature_gate?, 1},
             {BoundedAuthorityProtocol.V3.Es256, :canonical_signature, 1},
             {BoundedAuthorityProtocol.Es256, :canonical_signature?, 1}
           ])

  @contract_major_prefixes [
    "Elixir.BoundedAuthorityProtocol.V1",
    "Elixir.BoundedAuthorityProtocol.V2",
    "Elixir.BoundedAuthorityProtocol.V3"
  ]

  setup_all do
    %{graph: call_graph()}
  end

  test "no contract-major decode or parse function reaches a producer canonicality check", %{
    graph: graph
  } do
    roots =
      for {{module, function, arity} = mfa, _callees} <- graph,
          contract_major?(module),
          decode_or_parse?(function, arity),
          do: mfa

    # Known positives: the roots include the grant and proof decoders of every major, and
    # the anchor and transition parsers.
    for module <- [
          BoundedAuthorityProtocol.V1.Runtime,
          BoundedAuthorityProtocol.V2.Runtime,
          BoundedAuthorityProtocol.V3.Runtime
        ] do
      assert {module, :decode_grant, 2} in roots
      assert {module, :parse_grant, 2} in roots
    end

    assert {BoundedAuthorityProtocol.V3.BoundaryAnchorCodec, :parse, 2} in roots
    assert {BoundedAuthorityProtocol.V1.KeyTransitionCodec, :parse, 2} in roots

    for root <- roots do
      reached = reachable(graph, [root], MapSet.new())
      hits = MapSet.intersection(reached, @helpers)
      assert MapSet.size(hits) == 0, "#{inspect(root)} reaches #{inspect(MapSet.to_list(hits))}"
    end
  end

  test "the instrument sees the producer calls it rules out at decode", %{graph: graph} do
    assemble_v3 =
      reachable(
        graph,
        [{BoundedAuthorityProtocol.V3.Runtime, :assemble_compact, 3}],
        MapSet.new()
      )

    assert {BoundedAuthorityProtocol.V3.Es256, :canonical_signature, 1} in assemble_v3
    assert {BoundedAuthorityProtocol.Es256, :canonical_signature?, 1} in assemble_v3

    for module <- [BoundedAuthorityProtocol.V1.Runtime, BoundedAuthorityProtocol.V2.Runtime] do
      assert {BoundedAuthorityProtocol.Ed25519, :signature_gate?, 1} in reachable(
               graph,
               [{module, :assemble_compact, 3}],
               MapSet.new()
             )
    end

    for module <- [
          BoundedAuthorityProtocol.V1.AnchoredExportCodec,
          BoundedAuthorityProtocol.V2.AnchoredExportCodec
        ] do
      assert {BoundedAuthorityProtocol.Ed25519, :signature_gate?, 1} in reachable(
               graph,
               [{module, :encode, 2}],
               MapSet.new()
             )
    end

    assert {BoundedAuthorityProtocol.V3.Es256, :canonical_signature, 1} in reachable(
             graph,
             [{BoundedAuthorityProtocol.V3.AnchoredExportCodec, :encode, 2}],
             MapSet.new()
           )
  end

  # --- compiled call graph ---------------------------------------------------------------

  defp contract_major?(module) do
    name = Atom.to_string(module)
    Enum.any?(@contract_major_prefixes, &(name == &1 or String.starts_with?(name, &1 <> ".")))
  end

  defp decode_or_parse?(function, arity) do
    name = Atom.to_string(function)

    String.starts_with?(name, "decode_") or String.starts_with?(name, "parse_grant") or
      String.starts_with?(name, "parse_proof") or (name == "parse" and arity == 2)
  end

  defp reachable(_graph, [], seen), do: seen

  defp reachable(graph, [mfa | rest], seen) do
    if MapSet.member?(seen, mfa) do
      reachable(graph, rest, seen)
    else
      reachable(
        graph,
        MapSet.to_list(Map.get(graph, mfa, MapSet.new())) ++ rest,
        MapSet.put(seen, mfa)
      )
    end
  end

  defp call_graph do
    :bounded_authority_protocol
    |> Application.spec(:modules)
    |> Enum.flat_map(&module_edges/1)
    |> Map.new()
  end

  # Reads the beam files in the build's ebin directly, so a cover-compiled run still sees the
  # compiled code.
  defp module_edges(module) do
    path =
      :code.lib_dir(:bounded_authority_protocol)
      |> Path.join("ebin/#{module}.beam")
      |> String.to_charlist()

    {:ok, {^module, [abstract_code: {_abstract_format, forms}]}} =
      :beam_lib.chunks(path, [:abstract_code])

    for {:function, _line, name, arity, clauses} <- forms do
      {{module, name, arity}, calls(clauses, module, MapSet.new())}
    end
  end

  defp calls({:call, _line, {:atom, _, name}, args} = term, module, acc) do
    acc = MapSet.put(acc, {module, name, length(args)})
    descend(term, module, acc)
  end

  defp calls(
         {:call, _line, {:remote, _, {:atom, _, callee}, {:atom, _, name}}, args} = term,
         module,
         acc
       ) do
    acc = MapSet.put(acc, {callee, name, length(args)})
    descend(term, module, acc)
  end

  defp calls({:fun, _line, {:function, name, arity}}, module, acc)
       when is_atom(name) and is_integer(arity),
       do: MapSet.put(acc, {module, name, arity})

  defp calls(
         {:fun, _line, {:function, {:atom, _, callee}, {:atom, _, name}, {:integer, _, arity}}},
         _module,
         acc
       ),
       do: MapSet.put(acc, {callee, name, arity})

  defp calls(term, module, acc) when is_tuple(term), do: descend(term, module, acc)

  defp calls(term, module, acc) when is_list(term),
    do: Enum.reduce(term, acc, &calls(&1, module, &2))

  defp calls(_term, _module, acc), do: acc

  defp descend(term, module, acc),
    do: term |> Tuple.to_list() |> Enum.reduce(acc, &calls(&1, module, &2))
end
