defmodule BoundedAuthorityProtocol.ExtractFacts do
  # Spec-facts extractor (spec-decoupling L2). Reads the `<!-- facts:key -->` anchor-annotated
  # normative blocks of the CURRENT authority (spec/bap-v1.md since the authority swap; the
  # pre-swap extraction from docs/protocol-v1.md + ADR 0004 + registries.md is preserved
  # byte-for-byte in spec/facts/baseline-v1.json) and emits a deterministic, canonical-JSON
  # facts map. The swap certification was extract(spec) == baseline with an empty delta.
  #
  # The authority set is MAJOR-KEYED: each contract-major's closed profile is extracted from
  # its own spec file under its own closed anchor set, and frozen per major
  # (spec/facts/baseline-v<N>.json). Major 1's ten-key set and its baseline bytes are the
  # original swap certification and never change shape. Majors 2 and 3 (the successor closed
  # profiles, which incorporate v1 by enumerated reference) extract their DELTA facts — suite
  # identity, domain separators, selector kinds, and the v3 suite rules/constants — so a
  # silent edit of any successor-major normative constant reds rule 1b exactly as a v1 edit
  # does (ADR 0030's and ADR 0035 §9's named deferral, closed).
  #
  # Region rule: an anchor's region runs from the anchor line to the next `#` heading or the
  # next facts anchor, whichever comes first. Each major's anchor set is closed and each key
  # appears exactly once across that major's authority files; an unknown, missing, or
  # duplicated anchor fails extraction by name (check_spec_facts rule 10 enforces the v1
  # anchor placement against the live tree).
  #
  # Determinism: pure String/Enum parsing, no clock/env/network; output bytes are a canonical
  # serialization (sorted keys, compact separators) so equal facts always produce equal bytes.

  @root Path.expand("../..", __DIR__)

  @authority_files_by_major %{
    1 => ["spec/bap-v1.md"],
    2 => ["spec/bap-v2.md"],
    3 => ["spec/bap-v3.md"]
  }

  @anchor_keys_by_major %{
    1 => [
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
    ],
    2 => ["domain-separators", "selector-kinds", "suite-identity"],
    3 => [
      "domain-separators",
      "header-members",
      "suite-identity",
      "suite-rules",
      "suite-constants"
    ]
  }

  # Every authority file across every major (check_spec_facts rule 9's tracked-file sweep).
  def authority_files,
    do: @authority_files_by_major |> Map.values() |> List.flatten()

  def authority_files(major), do: Map.fetch!(@authority_files_by_major, major)
  def anchor_keys(major), do: Map.fetch!(@anchor_keys_by_major, major)

  # --- entry -----------------------------------------------------------------

  # Returns {:ok, facts_map} or {:error, reason_string}. extract/0 is major 1 (the original
  # swap-certified shape; kept so test/spec_facts_test.exs and the baselines stay stable).
  def extract, do: extract_major(1)

  def extract_major(major) when is_integer(major) do
    with {:ok, regions} <- collect_regions(major) do
      facts =
        Enum.reduce(anchor_keys(major), %{}, fn key, acc ->
          Map.put(acc, key, parse_region({key, major}, regions))
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

  defp collect_regions(major) do
    keys = anchor_keys(major)

    with {:ok, regions} <- collect(authority_files(major), keys, %{}) do
      found = Map.keys(regions) |> Enum.sort()

      if found == Enum.sort(keys) do
        {:ok, regions}
      else
        {:error,
         "major #{major}: anchor set mismatch: found #{inspect(found)}, expected #{inspect(Enum.sort(keys))} — " <>
           "an anchor is missing, duplicated, or unknown"}
      end
    end
  end

  defp collect([], _keys, regions), do: {:ok, regions}

  defp collect([file | rest], keys, regions) do
    path = Path.join(@root, file)

    with {:ok, contents} <- read(path),
         {:ok, file_regions} <- regions_of(contents, file, keys) do
      duplicates =
        Map.keys(regions) -- (Map.keys(regions) -- Map.keys(file_regions))

      case duplicates do
        [] ->
          collect(rest, keys, Map.merge(regions, file_regions))

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

  # Anchor validation BEFORE region building: the anchor set of each authority file must be a
  # permutation of the major's closed key list — no unknown key, no duplicate, no missing key.
  # This is the closed-set discipline v1 carries, enforced per file instead of per merged set.
  defp regions_of(contents, file, keys) do
    case validate_anchors(contents, file, keys) do
      :ok -> {:ok, build_regions(contents, keys)}
      {:error, _reason} = error -> error
    end
  end

  defp validate_anchors(contents, file, keys) do
    seen =
      contents
      |> String.split("\n")
      |> Enum.flat_map(fn line ->
        case Regex.run(~r{^<!-- facts:([a-z-]+) -->\s*$}, line) do
          [_, key] -> [key]
          _ -> []
        end
      end)

    unknown = seen -- keys
    dupes = seen -- Enum.uniq(seen)
    missing = keys -- Enum.uniq(seen)

    cond do
      seen == [] ->
        {:error, "#{file}: no facts anchors found"}

      unknown != [] ->
        {:error, "#{file}: unknown facts anchor(s) #{inspect(Enum.uniq(unknown))} — the major's anchor set is closed"}

      dupes != [] ->
        {:error, "#{file}: facts anchor(s) #{inspect(Enum.uniq(dupes))} appear more than once"}

      missing != [] ->
        {:error, "#{file}: missing facts anchor(s) #{inspect(missing)}"}

      true ->
        :ok
    end
  end

  # Splits the document into {anchor_key, region_lines} pairs. A region ends at the next
  # section heading (a line starting with "#" but not "###" — subsections continue a region,
  # which is what keeps ADR 0004's four ### blocks inside archive-framing) or at the next
  # anchor, whichever comes first.
  defp build_regions(contents, keys) do
    lines = String.split(contents, "\n")

    {regions, current, buffer} =
      Enum.reduce(lines, {%{}, nil, []}, fn line, {regions, current, buffer} ->
        cond do
          anchor_key = anchor?(line, keys) ->
            closed = close_current(regions, current, buffer)
            {closed, anchor_key, []}

          current != nil and String.starts_with?(line, "#") and
              not String.starts_with?(line, "###") ->
            {close_current(regions, current, buffer), nil, []}

          true ->
            {regions, current, [line | buffer]}
        end
      end)

    close_current(regions, current, buffer)
  end

  defp anchor?(line, keys) do
    case Regex.run(~r{^<!-- facts:([a-z-]+) -->\s*$}, line) do
      [_, key] -> if key in keys, do: key, else: nil
      _ -> nil
    end
  end

  defp close_current(regions, nil, _buffer), do: regions

  defp close_current(regions, key, buffer) do
    Map.put(regions, key, buffer |> Enum.reverse() |> Enum.join("\n"))
  end

  # --- per-key parsing --------------------------------------------------------

  defp parse_region({key, major}, regions) do
    do_parse_region({key, major}, Map.fetch!(regions, key), regions)
  end

  defp do_parse_region({"bounds", 1}, region, _regions) do
    parse_table(region)
    |> Enum.map(fn row ->
      [resource, maximum] = row
      {resource, parse_integer(maximum)}
    end)
    |> Map.new()
  end

  defp do_parse_region({"header-members", _major}, region, _regions) do
    parse_table(region)
    |> Enum.map(fn [kind, members] -> {kind, parse_members(members)} end)
    |> Map.new()
  end

  defp do_parse_region({"grant-claims", 1}, region, _regions) do
    %{"claims" => parse_claim_names(parse_table(region))}
  end

  defp do_parse_region({"proof-claims", 1}, region, _regions) do
    %{"claims" => parse_claim_names(parse_table(region))}
  end

  defp do_parse_region({"selector-kinds", _major}, region, _regions) do
    parse_table(region)
    |> Enum.map(fn [kind, interpretation] -> {kind, strip_markup(interpretation)} end)
    |> Map.new()
  end

  defp do_parse_region({"typ-values", 1}, region, _regions) do
    parse_table(region)
    |> Enum.map(fn [value, status, _purpose] ->
      %{"value" => strip_markup(value), "status" => strip_markup(status)}
    end)
  end

  defp do_parse_region({"domain-separators", 1}, region, regions) do
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

  # Majors 2 and 3 name their separators in the substitutions table; the wire spellings carry
  # the two-character \0 text (a literal NUL byte — the cd42445 incident class — does not
  # match and reds rule 1b).
  defp do_parse_region({"domain-separators", major}, region, _regions)
       when major in [2, 3] do
    prefix = "BAP" <> Integer.to_string(major)
    token = ~r/#{prefix}-[A-Z]+\\0/

    tokens =
      token
      |> Regex.scan(region)
      |> Enum.map(&hd/1)
      |> Enum.uniq()

    archive_prefixes =
      ~r/#{prefix}-ARCHIVE\\0EXPORT\\0/
      |> Regex.scan(region)
      |> Enum.map(&hd/1)
      |> Enum.uniq()

    %{
      "request" => Enum.filter(tokens, &String.starts_with?(&1, prefix <> "-REQUEST")),
      "chain" => Enum.filter(tokens, &String.starts_with?(&1, prefix <> "-CHAIN")),
      "archive" => archive_prefixes
    }
  end

  # Suite identity of a successor major: the major-bound suite name, the payload `v` integer,
  # and (when the profile restates it) the closed `alg` header value. Each is extracted only
  # when exactly one candidate is present; an absent or ambiguous value extracts as ""/-1,
  # which diverges from the frozen baseline and reds rule 1b.
  defp do_parse_region({"suite-identity", major}, region, _regions) when major in [2, 3] do
    prefix = "BAP" <> Integer.to_string(major)

    suite =
      sole(
        Regex.scan(~r/`(#{prefix}-[A-Za-z0-9]+-[A-Za-z0-9]+)`/, region)
        |> Enum.map(&Enum.at(&1, 1))
      )

    payload_v =
      case sole(Regex.scan(~r/is exactly\s+integer `(\d+)`/, region) |> Enum.map(&Enum.at(&1, 1))) do
        "" -> -1
        digits -> String.to_integer(digits)
      end

    alg =
      sole(
        Regex.scan(~r/`alg` header is exactly `([A-Za-z0-9-]+)`/, region)
        |> Enum.map(&Enum.at(&1, 1))
      )

    facts = %{"suite" => suite, "payload-v" => payload_v}

    if alg == "", do: facts, else: Map.put(facts, "alg", alg)
  end

  # The v3 signature suite's fixed rules (§3.1 keys + §3.2 signatures): curve, EC JWK member
  # set, coordinate/raw-key/signature widths, the raw r || s form, the low-S rule, the
  # rejected-encoding list, and the DER exclusion.
  defp do_parse_region({"suite-rules", 3}, region, _regions) do
    jwk =
      region
      |> fenced_blocks()
      |> Enum.find("", &String.starts_with?(&1, "{\"crv\""))

    jwk_members = jwk |> String.trim_leading("{") |> String.trim_trailing("}") |> member_names()

    coordinate_bytes =
      case Regex.run(~r/exactly (\d+)\s+bytes each/, region) do
        [_, digits] -> String.to_integer(digits)
        _ -> -1
      end

    raw_key_bytes =
      case Regex.run(~r/exactly (\d+) bytes, `0x04/, region) do
        [_, digits] -> String.to_integer(digits)
        _ -> -1
      end

    signature =
      case Regex.run(~r/exactly (\d+) bytes, `r \|\| s`/, region) do
        [_, digits] -> %{"form" => "r || s", "bytes" => String.to_integer(digits)}
        _ -> %{"form" => "", "bytes" => -1}
      end

    low_s = sole(Regex.scan(~r/`(s > n\/2)`/, region) |> Enum.map(&Enum.at(&1, 1)))

    rejected =
      ~r/`([rs] (=|≥|>) [^`]+)`/
      |> Regex.scan(region)
      |> Enum.map(&Enum.at(&1, 1))

    %{
      "curve" => jwk_member(jwk, "crv"),
      "jwk-members" => jwk_members,
      "jwk-kty" => jwk_member(jwk, "kty"),
      "coordinate-bytes" => coordinate_bytes,
      "raw-public-key-bytes" => raw_key_bytes,
      "signature" => signature,
      "low-s" => low_s,
      "rejected" => rejected,
      "der-on-wire" => if(String.contains?(region, "DER is never a v3 wire spelling"), do: "never", else: "")
    }
  end

  # The v3 fixed-width constants table (§5). Unlike the v1 tables, this table's labels carry
  # escaped pipes (`r \|\| s`), so cells split on unescaped pipes only and are unescaped
  # before use.
  defp do_parse_region({"suite-constants", 3}, region, _regions) do
    region
    |> String.split("\n")
    |> Enum.filter(&String.starts_with?(&1, "|"))
    |> Enum.reject(&separator_row?/1)
    |> Enum.drop(1)
    |> Enum.map(fn row ->
      [label, bytes] =
        row
        |> String.split(~r/(?<!\\)\|/)
        |> Enum.map(&(&1 |> String.replace("\\|", "|") |> String.trim()))
        |> Enum.reject(&(&1 == ""))

      {strip_markup(label), parse_integer(bytes)}
    end)
    |> Map.new()
  end

  defp do_parse_region({"digest-constructions", 1}, region, _regions) do
    fenced = fenced_blocks(region)

    %{
      "signing-input" => Enum.at(fenced, 0),
      "request-digest" => Enum.at(fenced, 1),
      "typed-projection" => typed_projection(region)
    }
  end

  defp do_parse_region({"archive-framing", 1}, region, _regions) do
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

  defp do_parse_region({"error-shape", 1}, region, _regions) do
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

  # The sole distinct candidate, or "" when absent/ambiguous — an ambiguous value never
  # freezes silently (it diverges from the frozen baseline and reds rule 1b).
  defp sole(candidates) do
    case Enum.uniq(candidates) do
      [only] -> only
      _ -> ""
    end
  end

  # Member names of a flat single-level JSON object literal: {"crv":"P-256","kty":"EC",...}
  # → ["crv", "kty", ...], in appearance order.
  defp member_names(object_literal) do
    object_literal
    |> String.split(",")
    |> Enum.map(&(&1 |> String.split(":") |> hd() |> String.trim(~s("))))
  end

  defp jwk_member(object_literal, name) do
    case Regex.run(~r/"#{name}":"([^"]+)"/, object_literal) do
      [_, value] -> value
      _ -> ""
    end
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

defmodule BoundedAuthorityProtocol.ExtractFacts.CLI do
  def print_facts(major) do
    case BoundedAuthorityProtocol.ExtractFacts.extract_major(major) do
      {:ok, facts} ->
        IO.puts(BoundedAuthorityProtocol.ExtractFacts.canonical(facts))

      {:error, reason} ->
        IO.puts(:stderr, "extract_facts: #{reason}")
        System.halt(1)
    end
  end

  def write_facts(major, target) do
    case BoundedAuthorityProtocol.ExtractFacts.extract_major(major) do
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
  end

  def parse_major!(major) do
    case Integer.parse(major) do
      {n, ""} when n in 1..3 -> n
      _ -> raise "extract_facts: --major expects 1, 2, or 3 (got #{inspect(major)})"
    end
  end
end

# CLI trailer: executes only under an explicit argv contract (--print, or --write TARGET) so
# requiring this file from the gate script stays side-effect free. --major N selects the
# major's extraction (default 1) — the successor baselines freeze with
# `--major 2 --write spec/facts/baseline-v2.json` and `--major 3 ...` exactly as v1's did.
case System.argv() do
  ["--print"] ->
    BoundedAuthorityProtocol.ExtractFacts.CLI.print_facts(1)

  ["--write", target] ->
    BoundedAuthorityProtocol.ExtractFacts.CLI.write_facts(1, target)

  ["--major", major, "--print"] ->
    BoundedAuthorityProtocol.ExtractFacts.CLI.print_facts(
      BoundedAuthorityProtocol.ExtractFacts.CLI.parse_major!(major)
    )

  ["--major", major, "--write", target] ->
    BoundedAuthorityProtocol.ExtractFacts.CLI.write_facts(
      BoundedAuthorityProtocol.ExtractFacts.CLI.parse_major!(major),
      target
    )

  _ ->
    :ok
end
