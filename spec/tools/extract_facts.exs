defmodule BoundedAuthorityProtocol.ExtractFacts do
  # Spec-facts extractor (spec-decoupling L2). Reads the `<!-- facts:key -->` anchor-annotated
  # normative blocks of the CURRENT authority (spec/bap-v1.md since the authority swap; the
  # pre-swap extraction from docs/protocol-v1.md + ADR 0004 + registries.md is preserved
  # byte-for-byte in spec/facts/baseline-v1.json) and emits a deterministic, canonical-JSON
  # facts map. The swap certification was extract(spec) == baseline with an empty delta.
  #
  # Region rule: an anchor's region runs from the anchor line to the next `#` heading or the
  # next facts anchor, whichever comes first. The anchor set is closed — exactly the ten keys
  # below, each exactly once across the authority set. The extractor refuses anything else
  # (check_spec_facts rule 10 enforces it against the live tree).
  #
  # Determinism: pure String/Enum parsing, no clock/env/network; output bytes are a canonical
  # serialization (sorted keys, compact separators) so equal facts always produce equal bytes.

  @root Path.expand("../..", __DIR__)

  # The single normative authority since the spec swap: every facts anchor lives in the spec.
  # (docs/protocol-v1.md becomes a generated derived view; ADR 0004 and registries.md retain
  # their content as extended records — none is extracted.)
  @authority_files [
    "spec/bap-v1.md"
  ]

  @anchor_keys [
    "bounds",
    "header-members",
    "grant-claims",
    "proof-claims",
    "selector-kinds",
    "typ-values",
    "domain-separators",
    "digest-constructions",
    "archive-framing",
    "error-shape"
  ]

  def authority_files, do: @authority_files
  def anchor_keys, do: @anchor_keys

  # --- entry -----------------------------------------------------------------

  # Returns {:ok, facts_map} or {:error, reason_string}.
  def extract do
    with {:ok, regions} <- collect_regions() do
      facts =
        Enum.reduce(@anchor_keys, %{}, fn key, acc ->
          Map.put(acc, key, parse_region(key, regions))
        end)

      {:ok, facts}
    end
  end

  # Canonical bytes of the facts map (sorted keys, compact separators).
  def canonical(facts) when is_map(facts), do: canonical_value(facts)

  defp canonical_value(map) when is_map(map) do
    inner =
      map
      |> Enum.map(fn {k, v} -> ~s("#{k}":) <> canonical_value(v) end)
      |> Enum.sort()
      |> Enum.join(",")

    "{" <> inner <> "}"
  end

  defp canonical_value(list) when is_list(list) do
    "[" <> Enum.map_join(list, ",", &canonical_value/1) <> "]"
  end

  defp canonical_value(value) when is_binary(value), do: ~s("#{escape(value)}")
  defp canonical_value(value) when is_integer(value), do: Integer.to_string(value)

  defp escape(value) do
    value |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")
  end

  # --- region collection ------------------------------------------------------

  defp collect_regions do
    with {:ok, regions} <- collect(@authority_files, %{}) do
      keys = Map.keys(regions) |> Enum.sort()
      expected = Enum.sort(@anchor_keys)

      if keys == expected do
        {:ok, regions}
      else
        {:error,
         "anchor set mismatch: found #{inspect(keys)}, expected #{inspect(expected)} — " <>
           "an anchor is missing, duplicated, or unknown"}
      end
    end
  end

  defp collect([], regions), do: {:ok, regions}

  defp collect([file | rest], regions) do
    path = Path.join(@root, file)

    with {:ok, contents} <- read(path),
         {:ok, file_regions} <- regions_of(contents, file) do
      duplicates =
        Map.keys(regions) -- (Map.keys(regions) -- Map.keys(file_regions))

      case duplicates do
        [] ->
          collect(rest, Map.merge(regions, file_regions))

        [key | _] ->
          {:error, "anchor #{inspect(key)} appears in more than one authority file"}
      end
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, contents} -> {:ok, contents}
      {:error, reason} -> {:error, "cannot read #{path}: #{inspect(reason)}"}
    end
  end

  # Splits the document into {anchor_key, region_lines} pairs. A region ends at the next
  # section heading (a line starting with "#" but not "###" — subsections continue a region,
  # which is what keeps ADR 0004's four ### blocks inside archive-framing) or at the next
  # anchor, whichever comes first.
  defp regions_of(contents, file) do
    lines = String.split(contents, "\n")

    {regions, current, buffer} =
      Enum.reduce(lines, {%{}, nil, []}, fn line, {regions, current, buffer} ->
        cond do
          anchor_key = anchor?(line) ->
            closed = close_current(regions, current, buffer)
            {closed, anchor_key, []}

          current != nil and String.starts_with?(line, "#") and
              not String.starts_with?(line, "###") ->
            {close_current(regions, current, buffer), nil, []}

          true ->
            {regions, current, [line | buffer]}
        end
      end)

    regions = close_current(regions, current, buffer)

    if map_size(regions) == 0 do
      {:error, "#{file}: no facts anchors found"}
    else
      {:ok, regions}
    end
  end

  defp anchor?(line) do
    case Regex.run(~r{^<!-- facts:([a-z-]+) -->\s*$}, line) do
      [_, key] -> if key in @anchor_keys, do: key, else: nil
      _ -> nil
    end
  end

  defp close_current(regions, nil, _buffer), do: regions

  defp close_current(regions, key, buffer) do
    Map.put(regions, key, buffer |> Enum.reverse() |> Enum.join("\n"))
  end

  # --- per-key parsing --------------------------------------------------------

  defp parse_region(key, regions) do
    do_parse_region(key, Map.fetch!(regions, key), regions)
  end

  defp do_parse_region("bounds", region, _regions) do
    parse_table(region)
    |> Enum.map(fn row ->
      [resource, maximum] = row
      {resource, parse_integer(maximum)}
    end)
    |> Map.new()
  end

  defp do_parse_region("header-members", region, _regions) do
    parse_table(region)
    |> Enum.map(fn [kind, members] -> {kind, parse_members(members)} end)
    |> Map.new()
  end

  defp do_parse_region("grant-claims", region, _regions) do
    %{"claims" => parse_claim_names(parse_table(region))}
  end

  defp do_parse_region("proof-claims", region, _regions) do
    %{"claims" => parse_claim_names(parse_table(region))}
  end

  defp do_parse_region("selector-kinds", region, _regions) do
    parse_table(region)
    |> Enum.map(fn [kind, interpretation] -> {kind, strip_markup(interpretation)} end)
    |> Map.new()
  end

  defp do_parse_region("typ-values", region, _regions) do
    parse_table(region)
    |> Enum.map(fn [value, status, _purpose] ->
      %{"value" => strip_markup(value), "status" => strip_markup(status)}
    end)
  end

  defp do_parse_region("domain-separators", region, regions) do
    # The request separator appears inside the request-digest construction (the
    # digest-constructions region); reserved/retired separators are named in this region.
    digest_region = Map.fetch!(regions, "digest-constructions")

    request =
      if String.contains?(digest_region, "BAP1-REQUEST\\0"), do: ["BAP1-REQUEST\\0"], else: []

    tokens =
      (Regex.scan(~r/BAP1-[A-Z]+\\0/, region) ++ Regex.scan(~r/BAP1-[A-Z]+\\0/, digest_region))
      |> Enum.map(&hd/1)
      |> Enum.uniq()

    %{
      "request" => request,
      "reserved" => Enum.filter(tokens, &(&1 in ["BAP1-CHAIN\\0", "BAP1-ARCHIVE\\0"])),
      "retired" => Enum.filter(tokens, &(&1 in ["BAP1-GRANT\\0", "BAP1-PROOF\\0"]))
    }
  end

  defp do_parse_region("digest-constructions", region, _regions) do
    fenced = fenced_blocks(region)

    %{
      "signing-input" => Enum.at(fenced, 0),
      "request-digest" => Enum.at(fenced, 1),
      "typed-projection" => typed_projection(region)
    }
  end

  defp do_parse_region("archive-framing", region, _regions) do
    row_members =
      case Regex.run(~r/\{"chain_id".*?\}/, region) do
        [row] ->
          row
          |> String.trim_leading("{")
          |> String.trim_trailing("}")
          |> String.split(",")
          |> Enum.map(&(&1 |> String.split(":") |> hd() |> String.trim(~s("))))

        _ ->
          []
      end

    archive_prefix =
      case Regex.run(~r/"(BAP1-ARCHIVE\\0EXPORT\\0)"/, region) do
        [_, prefix] -> prefix
        _ -> ""
      end

    %{
      "row-members" => row_members,
      "row-hash-prefix" => "BAP1-CHAIN\\0",
      "archive-prefix" => archive_prefix,
      "frame" => frame_rule(region),
      "anchor-typ" => anchored_string(region, "ba+chain-anchor"),
      "transition-typ" => anchored_string(region, "ba+key-transition"),
      "ceiling-expression" => ceiling_expression(region)
    }
  end

  defp do_parse_region("error-shape", region, _regions) do
    if String.contains?(region, "{:error, :invalid}") do
      %{"value" => "{:error, :invalid}"}
    else
      %{"value" => ""}
    end
  end

  # --- parsing helpers --------------------------------------------------------

  # "65,536" | "9,007,199,254,740,991" | "32 / 64" (kept as a list) → integers.
  defp parse_integer(text) do
    case Regex.scan(~r/[0-9][0-9,]*/, text) do
      [[match]] ->
        match |> String.replace(",", "") |> String.to_integer()

      numbers ->
        numbers |> Enum.map(&(&1 |> hd() |> String.replace(",", "") |> String.to_integer()))
    end
  end

  # Markdown table rows → lists of raw cell strings (backticks/whitespace preserved).
  defp parse_table(region) do
    region
    |> String.split("\n")
    |> Enum.filter(&String.starts_with?(&1, "|"))
    |> Enum.reject(&separator_row?/1)
    |> Enum.drop(1)
    |> Enum.map(fn row ->
      row
      |> String.trim_leading("|")
      |> String.trim_trailing("|")
      |> String.split("|")
      |> Enum.map(&String.trim/1)
    end)
    |> Enum.reject(&(&1 == []))
    |> Enum.reject(fn cells -> Enum.any?(cells, &(&1 == "")) end)
  end

  defp separator_row?(row), do: Regex.match?(~r/^\|[\s\-|:]+\|$/, row)

  # `alg: "EdDSA"`, `typ: "ba+cap"`, `kid: key_identifier` → ["alg", "typ", "kid"]
  defp parse_members(cell) do
    ~r/`([a-zA-Z0-9_]+):/
    |> Regex.scan(cell)
    |> Enum.map(fn [_, name] -> name end)
  end

  # Claim-table first column: `v`, `iss`, `jti`, ... → names. A cell may list several names.
  defp parse_claim_names(rows) do
    rows
    |> Enum.flat_map(fn [names | _] ->
      ~r/`([a-zA-Z0-9_]+)`/
      |> Regex.scan(names)
      |> Enum.map(fn [_, name] -> name end)
    end)
    |> Enum.uniq()
  end

  defp strip_markup(text) do
    text |> String.replace("`", "") |> String.trim()
  end

  defp fenced_blocks(region) do
    ~r/```[a-z]*\n(.*?)```/s
    |> Regex.scan(region)
    |> Enum.map(fn [_, block] -> String.trim_trailing(block, "\n") end)
  end

  defp typed_projection(region) do
    parse_table(region)
    |> Enum.map(fn [tagged, projected] ->
      %{"tagged" => strip_markup(tagged), "projected" => strip_markup(projected)}
    end)
  end

  defp frame_rule(region) do
    case Regex.run(~r/`(UINT32_BE\([^)]*\) \|\| bytes)`/, region) do
      [_, rule] -> rule
      _ -> ""
    end
  end

  defp anchored_string(region, value) do
    if String.contains?(region, value), do: value, else: ""
  end

  defp ceiling_expression(region) do
    Enum.find(fenced_blocks(region), "", &String.starts_with?(&1, "20 +"))
  end
end

# CLI trailer: executes only under an explicit argv contract (--print, or --write TARGET) so
# requiring this file from the gate script stays side-effect free.
case System.argv() do
  ["--print"] ->
    case BoundedAuthorityProtocol.ExtractFacts.extract() do
      {:ok, facts} ->
        IO.puts(BoundedAuthorityProtocol.ExtractFacts.canonical(facts))

      {:error, reason} ->
        IO.puts(:stderr, "extract_facts: #{reason}")
        System.halt(1)
    end

  ["--write", target] ->
    case BoundedAuthorityProtocol.ExtractFacts.extract() do
      {:ok, facts} ->
        File.write!(
          Path.expand(target),
          BoundedAuthorityProtocol.ExtractFacts.canonical(facts) <> "\n"
        )

        IO.puts("extract_facts: wrote #{target}")

      {:error, reason} ->
        IO.puts(:stderr, "extract_facts: #{reason}")
        System.halt(1)
    end

  _ ->
    :ok
end
