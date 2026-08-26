defmodule BoundedAuthorityProtocol.BuildExamples do
  # Spec Appendix A generator (spec-decoupling L3). Selects representative conformance-corpus
  # cases by id and embeds their exact public artifacts — compact bytes, public keys, expected
  # facts or the single rejection outcome — into spec/bap-v1.md between the examples markers.
  # Corpus PUBLIC keys only (critical rule 6: no private material can appear — the corpus
  # itself is public-only and this tool copies verbatim).
  #
  # Deterministic: same corpus + same spec -> byte-identical appendix. The regeneration gate
  # (this file in --check mode, wired as a spec-facts rule) reds on a hand-edited example byte
  # and on a missing/deleted cited case id.
  #
  # Usage:
  #   mix run --no-start spec/tools/build_examples.exs          # check: committed == rebuilt
  #   mix run --no-start spec/tools/build_examples.exs --write  # regenerate Appendix A

  @root Path.expand("../..", __DIR__)
  @spec_path "spec/bap-v1.md"
  @begin_marker "<!-- examples:begin -->"
  @end_marker "<!-- examples:end -->"

  # One valid exemplar per verifying surface family, plus rejected exemplars across the
  # invalid-class families. Case ids are corpus-stable; a renamed/deleted id reds the rebuild
  # (cited id missing), which is the non-vacuity leg.
  @valid_examples [
    {"grant-decode-valid", "A valid grant (decode surface)"},
    {"proof-decode-valid", "A valid holder proof (decode surface)"},
    
    {"verify-grant-valid", "A valid grant (verification surface)"},
    {"check-envelope-valid", "A valid request envelope"},
    {"check-chain-valid", "A valid consumption chain"},
    {"verify-anchored-export-valid", "A valid anchored export"}
  ]

  @rejected_examples [
    {"grant-decode-invalid-encoding", "Rejected: malformed encoding (decode surface)"},
    {"grant-decode-invalid-algorithm-none", "Rejected: algorithm none"},
    {"decode-grant-invalid-encoding-times-iat-ge-exp", "Rejected: incoherent signed times"},
    {"decode-grant-invalid-encoding-audiences-duplicate", "Rejected: duplicate audience"},
    {"check-envelope-invalid-claim-holder-binding", "Rejected: holder binding mismatch"},
    {"check-envelope-invalid-selector", "Rejected: selector-disallowed arguments"},
    {"check-envelope-invalid-nonce-required", "Rejected: missing required nonce"}
  ]

  def run(argv) do
    cases = load_corpus_cases()
    rendered = render(cases)

    case argv do
      ["--write"] ->
        write_appendix(rendered)
        IO.puts("build_examples: rewrote Appendix A (#{length(@valid_examples) + length(@rejected_examples)} examples)")

      _ ->
        check_appendix(rendered)
    end
  end

  defp load_corpus_cases do
    dir = Path.join(@root, "priv/conformance/v1/corpus")

    walk = fn walk, d ->
      File.ls!(d)
      |> Enum.flat_map(fn e ->
        p = Path.join(d, e)
        if File.dir?(p), do: walk.(walk, p), else: [p]
      end)
    end

    walk.(walk, dir)
    |> Enum.filter(&String.ends_with?(&1, ".json"))
    |> Enum.flat_map(fn p ->
      p |> File.read!() |> Jasonless.decode() |> Map.get("cases", [])
    end)
    |> Map.new(fn c -> {c["id"], c} end)
  end

  defp render(cases) do
    valid = render_group(cases, @valid_examples, "## A.1. Accepted examples")
    rejected = render_group(cases, @rejected_examples, "## A.2. Rejected examples")

    """
    #{@begin_marker}
    #{String.trim_trailing(valid)}

    #{String.trim_trailing(rejected)}
    #{@end_marker}
    """
    |> String.trim_trailing()
  end

  defp render_group(cases, selections, heading) do
    body =
      Enum.map_join(selections, "\n", fn {id, title} ->
        case Map.fetch(cases, id) do
          {:ok, case_obj} ->
            render_case(id, title, case_obj)

          :error ->
            raise "cited example case #{inspect(id)} is missing from the corpus — re-pin Appendix A"
        end
      end)

    heading <> "\n\n" <> body
  end

  defp render_case(id, title, case_obj) do
    input = case_obj["input"]
    verdict = case_obj["expected"]["verdict"]

    fields =
      Enum.map_join(compact_fields(input), fn {label, value} ->
        "- **#{label}:** `#{value}`\n"
      end)

    """
    ### #{title}

    Corpus case `#{id}` (surface `#{case_obj["surface"]}`, class `#{case_obj["class"]}`).

    #{fields}- **Outcome:** #{outcome_text(verdict)}
    """
  end

  # Public artifacts only: compacts and public key material; never expected-context secrets
  # (the corpus carries none — public keys only by construction).
  defp compact_fields(input) do
    for {key, value} <- [{"compact", input["compact"]}, {"grant", input["grant"]},
                          {"proof", input["proof"]}, {"key", input["key"]},
                          {"current key", input["current_key"]}, {"next key", input["next_key"]},
                          {"keys", join_list(input["keys"])}],
        is_binary(value) and value != "",
        do: {String.capitalize(key), value}
  end

  defp join_list(list) when is_list(list) do
    if Enum.all?(list, &is_binary/1), do: Enum.join(list, ", "), else: nil
  end

  defp join_list(_), do: nil

  defp outcome_text("valid"), do: "accepted — verification succeeds with redacted, non-authorizing facts"
  defp outcome_text("invalid"), do: "rejected — the single closed error value, no other observable"

  defp write_appendix(rendered) do
    path = Path.join(@root, @spec_path)
    File.write!(path, replace_region(File.read!(path), rendered))
  end

  defp check_appendix(rendered) do
    path = Path.join(@root, @spec_path)
    current = current_region(File.read!(path))

    if current == rendered do
      IO.puts("build_examples: Appendix A matches the rebuild (#{byte_size(rendered)} bytes)")
    else
      IO.puts(:stderr, "build_examples: Appendix A does NOT match the rebuild — regenerate with --write or revert the hand edit")
      System.halt(1)
    end
  end

  defp current_region(text) do
    case String.split(text, @begin_marker) do
      [_, rest] ->
        case String.split(rest, @end_marker) do
          [region, _] -> @begin_marker <> region <> @end_marker
          _ -> raise "examples end marker missing from the spec"
        end

      _ ->
        raise "examples begin marker missing from the spec"
    end
  end

  defp replace_region(text, rendered) do
    [before, rest] = String.split(text, @begin_marker)
    [_region, after_part] = String.split(rest, @end_marker)
    before <> rendered <> after_part
  end
end

defmodule Jasonless do
  # The package's own bounded decoder, projected to plain values (no JSON dependency).
  alias BoundedAuthorityProtocol.V1.{Bounds, Json}

  def decode(bytes) do
    {:ok, tagged} = Json.decode(bytes, Bounds.maximum())
    plain(tagged)
  end

  defp plain({:object, members}),
    do: members |> Enum.map(fn {k, v} -> {k, plain(v)} end) |> Map.new()

  defp plain({:array, items}), do: Enum.map(items, &plain/1)
  defp plain({:string, s}), do: s
  defp plain({:integer, n}), do: n
  defp plain({:float, n}), do: n
  defp plain({:boolean, b}), do: b
  defp plain(:null), do: nil
end

BoundedAuthorityProtocol.BuildExamples.run(System.argv())
