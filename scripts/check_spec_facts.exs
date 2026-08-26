Code.require_file("../spec/tools/extract_facts.exs", __DIR__)
Code.require_file("../tools/architecture_gate.exs", __DIR__)

defmodule BoundedAuthorityProtocol.SpecFactsGate do
  # Spec-facts gate (spec-decoupling L2). Proves the CURRENT authority's normative facts agree
  # with the live implementation, the conformance corpus, and the requirement map — the drift
  # detector the whole migration rests on. Runs GREEN against the OLD authority today (that is
  # the point: the guards are proven against the world they protect before the authority swap);
  # after the swap the same gate runs unchanged against spec/bap-v1.md.
  #
  # Rules (numbers are stable identifiers; 1 lives in test/spec_facts_test.exs — it needs the
  # compiled Bounds module; 7/8/11 arrive with the IANA templates, the formal models, and the
  # keyword census landings):
  #
  #   2  spec closed sets ⊇ corpus valid-case member unions (direction-aware; spec members no
  #      valid case exercises require an optional-unobserved mark in spec/facts/coverage-v1.json)
  #   3  spec REQ-id set == requirement-map id set; each id defined exactly once in the map
  #   4  requirement-map statement hashes == spec/facts/requirement-statements-v1.json (frozen;
  #      a reworded requirement without a baseline bump is silent softening and reds)
  #   5  every map-cited `index.json <surface>.<class>=<count>` re-derives from the live corpus
  #   6  the map's blanket corpus revision integer == revision.json's integer
  #   9  vendor neutrality: every file this gate and the extractor read is git-tracked — inside
  #      the public-surface privacy gate's full-tree canary sweep (ADR 0023 topology; the term
  #      list itself is NEVER tracked, the privacy test's hash-canary scheme is the enforcement)
  #   10 anchor completeness: every markdown table in the authority docs sits inside exactly one
  #      anchored region and the anchor set is exactly the closed ten keys
  #
  # A failing rule names the rule id and the divergent pole pair, so a future editor is told
  # WHAT diverged, not just that something did.

  alias BoundedAuthorityProtocol.ExtractFacts
  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json

  @root Path.expand("..", __DIR__)
  @map_path "docs/design/requirement-map.md"
  @revision_path "priv/conformance/v1/corpus/revision.json"
  @index_path "priv/conformance/v1/corpus/index.json"
  @baseline_dir "spec/facts"

  @spec_docs ExtractFacts.authority_files()

  def run do
    started = System.monotonic_time(:millisecond)

    with {:ok, facts} <- ExtractFacts.extract(),
         problems <-
           rule_1_baseline_equality(facts) ++
             rule_2_closed_sets(facts) ++
             rule_3_requirement_ids() ++
             rule_4_statement_hashes() ++
             rule_5_cited_counts() ++
             rule_6_revision_citation() ++
             rule_9_vendor_neutrality() ++
             rule_10_anchor_completeness(facts),
         [] <- problems do
      elapsed = System.monotonic_time(:millisecond) - started
      IO.puts("spec facts gate: ok rules=[1b,2,3,4,5,6,9,10] in #{elapsed}ms")
    else
      problems when is_list(problems) ->
        IO.puts(:stderr, "spec facts gate FAILED:\n" <> Enum.join(problems, "\n"))
        System.halt(1)

      {:error, reason} ->
        IO.puts(:stderr, "spec facts gate: extraction failed: #{reason}")
        System.halt(1)
    end
  end

  # --- rule 1b: extraction == frozen baseline ---------------------------------
  #
  # Rule 1 has two poles: the test-time Bounds dump equality (test/spec_facts_test.exs) and this
  # byte equality against the frozen baseline. Any authority edit that changes extracted facts —
  # a bounds digit, a claim row, a construction byte — reds here until the baseline is
  # deliberately re-frozen. This is also the L3 certification mechanism: after the authority
  # swap, extract(new spec) == baseline-v1.json must hold with an empty delta.

  defp rule_1_baseline_equality(facts) do
    path = Path.join(@root, "#{@baseline_dir}/baseline-v1.json")

    case File.read(path) do
      {:ok, bytes} ->
        live = ExtractFacts.canonical(facts) <> "\n"

        if bytes == live do
          []
        else
          [
            "rule 1b: the extracted facts diverge from spec/facts/baseline-v1.json — re-freeze deliberately (a silent facts change is exactly what this gate exists to catch)"
          ]
        end

      _ ->
        [
          "rule 1b: spec/facts/baseline-v1.json is missing — the frozen pre-swap extraction is gone"
        ]
    end
  end

  # --- rule 2: closed sets ⊇ corpus valid-case unions ------------------------

  defp rule_2_closed_sets(facts) do
    {observed, integrity} = corpus_member_unions()

    case integrity do
      :ok ->
        spec_sets = %{
          "grant-claims" => Map.fetch!(facts["grant-claims"], "claims") |> MapSet.new(),
          "proof-claims" => Map.fetch!(facts["proof-claims"], "claims") |> MapSet.new(),
          "header-members.grant" => facts["header-members"]["grant"] |> MapSet.new(),
          "header-members.proof" => facts["header-members"]["proof"] |> MapSet.new(),
          "typ-values" =>
            facts["typ-values"]
            |> Enum.filter(&(&1["status"] == "active"))
            |> Enum.map(& &1["value"])
            |> MapSet.new(),
          "selector-kinds" =>
            facts["selector-kinds"]
            |> Map.keys()
            |> Enum.map(&String.replace(&1, "-", "_"))
            |> MapSet.new()
        }

        marks = coverage_marks()
        marked = marked_members(marks)

        Enum.flat_map(observed, fn {set_name, union} ->
          spec = Map.fetch!(spec_sets, set_name)

          Enum.flat_map(union, fn member ->
            cond do
              MapSet.member?(spec, member) ->
                []

              true ->
                [
                  "rule 2 (#{set_name}): corpus valid cases observe member #{inspect(member)} that the spec does not declare"
                ]
            end
          end)
        end) ++
          Enum.flat_map(spec_sets, fn {set_name, spec} ->
            observed_union = Map.get(observed, set_name, MapSet.new())

            Enum.flat_map(spec, fn member ->
              cond do
                MapSet.member?(observed_union, member) ->
                  []

                MapSet.member?(marked, "#{set_name}/#{member}") ->
                  []

                true ->
                  [
                    "rule 2 (#{set_name}): spec member #{inspect(member)} is exercised by NO valid corpus case and carries no optional-unobserved mark in spec/facts/coverage-v1.json"
                  ]
              end
            end)
          end)

      :invalid ->
        [
          "rule 2: the conformance corpus failed its own integrity load — cannot derive observed member unions"
        ]
    end
  end

  # Walks the corpus's valid cases carrying compact JWS inputs and unions the observed member
  # sets (claims, header members, typ values, selector kinds). Pure parsing — no verification.
  defp corpus_member_unions do
    map = corpus_file_map()

    case BoundedAuthorityProtocol.Conformance.Corpus.load(map) do
      {:ok, corpus} ->
        grants = valid_cases_with(corpus, ["decode_grant", "verify_grant", "check_envelope"])
        proofs = valid_cases_with(corpus, ["decode_proof", "check_envelope"])

        anchor_bearing =
          valid_cases_with(corpus, [
            "verify_historical_anchor",
            "verify_key_transition",
            "boundary_anchor_signing_input",
            "key_transition_signing_input"
          ])

        observed = %{
          "grant-claims" => union_payload_members(grants, "ba+cap"),
          "proof-claims" => union_payload_members(proofs, "dpop+jwt"),
          "header-members.grant" => union_header_members(grants, "ba+cap"),
          "header-members.proof" => union_header_members(proofs, "dpop+jwt"),
          "typ-values" => union_typs(grants ++ proofs ++ anchor_bearing),
          "selector-kinds" => union_selector_kinds(grants)
        }

        {observed, :ok}

      {:error, :invalid} ->
        {%{}, :invalid}
    end
  end

  defp corpus_file_map do
    @index_path
    |> Path.dirname()
    |> corpus_dir_files()
    |> Map.new(fn path ->
      rel = path |> Path.relative_to(Path.dirname(@index_path)) |> to_string()
      {rel, File.read!(path)}
    end)
  end

  defp corpus_dir_files(dir) do
    case File.ls(dir) do
      {:ok, entries} ->
        Enum.flat_map(entries, fn entry ->
          full = Path.join(dir, entry)

          if File.dir?(full) do
            corpus_dir_files(full)
          else
            [full]
          end
        end)

      _ ->
        []
    end
  end

  defp valid_cases_with(corpus, surfaces) do
    corpus.cases
    |> Enum.flat_map(&elem(&1, 1))
    |> Enum.filter(fn c -> c["expected"]["verdict"] == "valid" and c["surface"] in surfaces end)
  end

  defp compact_input(case_obj),
    do: case_obj["input"]["compact"] || case_obj["input"]["grant"] || case_obj["input"]["proof"]

  defp decode_compact(case_obj, want_typ) do
    with compact when is_binary(compact) <- compact_input(case_obj),
         [header_b64, payload_b64 | _] <- String.split(compact, "."),
         {:ok, header_json} <- Base.url_decode64(header_b64, padding: false),
         {:ok, payload_json} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, header_tagged} <- Json.decode(header_json, Bounds.maximum()),
         {:ok, payload_tagged} <- Json.decode(payload_json, Bounds.maximum()),
         {:ok, header} <- plain_object(header_tagged),
         {:ok, payload} <- plain_object(payload_tagged),
         true <- want_typ == :any or header["typ"] == want_typ do
      {:ok, header, payload}
    else
      _ -> :skip
    end
  end

  defp plain_object({:object, _members} = tagged) do
    case plain(tagged) do
      map when is_map(map) -> {:ok, map}
      _ -> :error
    end
  end

  defp plain_object(_), do: :error

  defp union_payload_members(cases, typ) do
    cases
    |> Enum.flat_map(fn c ->
      case decode_compact(c, typ) do
        {:ok, _header, payload} when is_map(payload) -> Map.keys(payload)
        _ -> []
      end
    end)
    |> MapSet.new()
  end

  defp union_header_members(cases, typ) do
    cases
    |> Enum.flat_map(fn c ->
      case decode_compact(c, typ) do
        {:ok, header, _payload} when is_map(header) -> Map.keys(header)
        _ -> []
      end
    end)
    |> MapSet.new()
  end

  defp union_typs(bearing_cases) do
    bearing_cases
    |> Enum.flat_map(fn c ->
      case decode_compact(c, :any) do
        {:ok, %{"typ" => typ}, _} -> [typ]
        _ -> []
      end
    end)
    |> MapSet.new()
  end

  defp union_selector_kinds(grant_cases) do
    grant_cases
    |> Enum.flat_map(fn c ->
      case decode_compact(c, "ba+cap") do
        {:ok, _header, payload} ->
          payload
          |> Map.get("operations", [])
          |> Enum.flat_map(fn op -> Map.get(op, "selectors", []) end)
          |> Enum.map(fn s -> Map.get(s, "kind") end)
          |> Enum.reject(&is_nil/1)

        _ ->
          []
      end
    end)
    |> MapSet.new()
  end

  # coverage-v1.json: {"marks": [{"set": ..., "member": ..., "reason": ...}]}
  defp coverage_marks do
    path = Path.join(@root, "#{@baseline_dir}/coverage-v1.json")

    case File.read(path) do
      {:ok, bytes} ->
        case Json.decode(bytes, Bounds.maximum()) do
          {:ok, tagged} -> plain(tagged)["marks"] || []
          _ -> []
        end

      _ ->
        []
    end
  end

  defp marked_members(marks) do
    marks |> Enum.map(&"#{&1["set"]}/#{&1["member"]}") |> MapSet.new()
  end

  # --- rule 3: REQ-id set equality --------------------------------------------

  defp rule_3_requirement_ids do
    spec_ids = spec_req_ids()
    {map_ids, duplicates} = map_req_ids()

    cond do
      duplicates != [] ->
        ["rule 3: requirement-map defines #{inspect(duplicates)} more than once"]

      MapSet.equal?(spec_ids, map_ids) ->
        []

      true ->
        only_spec = MapSet.difference(spec_ids, map_ids) |> Enum.sort()
        only_map = MapSet.difference(map_ids, spec_ids) |> Enum.sort()

        [
          "rule 3: REQ-id sets diverge — spec-only #{inspect(only_spec)}, map-only #{inspect(only_map)}"
        ]
    end
  end

  defp spec_req_ids do
    spec_docs = ["docs/protocol-v1.md", "docs/design/standards-track.md"]

    spec_docs
    |> Enum.flat_map(fn doc ->
      path = Path.join(@root, doc)

      ~r/`((?:REQ1-[A-Z0-9]+-[a-z0-9-]+))`/
      |> Regex.scan(File.read!(path))
      |> Enum.map(fn [_, id] -> id end)
    end)
    |> MapSet.new()
  end

  defp map_req_ids do
    rows = map_rows()

    ids =
      rows
      |> Enum.flat_map(fn [id | _] -> row_ids(id) end)

    duplicates =
      ids
      |> Enum.frequencies()
      |> Enum.filter(fn {_id, n} -> n > 1 end)
      |> Enum.map(&elem(&1, 0))

    {MapSet.new(ids), duplicates}
  end

  # --- rule 4: statement hashes -----------------------------------------------

  defp rule_4_statement_hashes do
    baseline = statement_baseline()
    live = live_statement_hashes()

    cond do
      baseline == %{} ->
        ["rule 4: spec/facts/requirement-statements-v1.json is missing or empty"]

      MapSet.equal?(MapSet.new(Map.keys(live)), MapSet.new(Map.keys(baseline))) ->
        diverged =
          for {id, hash} <- live,
              baseline[id] != hash,
              do:
                "rule 4: requirement #{id} statement diverges from the frozen baseline (silent softening — bump the baseline deliberately or revert)"

        diverged

      true ->
        only_live = Map.keys(live) -- Map.keys(baseline)
        only_base = Map.keys(baseline) -- Map.keys(live)

        [
          "rule 4: requirement id sets diverge — live-only #{inspect(only_live)}, baseline-only #{inspect(only_base)}"
        ]
    end
  end

  # One row may carry several ids ("id-a; id-b"); the statement hash is per ROW, keyed by the
  # row's sorted id list so cosmetic id ordering cannot fake a re-hash need (or hide one).
  defp live_statement_hashes do
    map_rows()
    |> Enum.map(fn [ids, statement | _] ->
      key = ids |> row_ids() |> Enum.sort() |> Enum.join(";")
      {key, :crypto.hash(:sha256, String.trim(statement)) |> Base.encode16(case: :lower)}
    end)
    |> Map.new()
  end

  defp row_ids(id_cell) do
    id_cell
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&String.trim(&1, "`"))
    |> Enum.reject(&(&1 == ""))
  end

  defp statement_baseline do
    path = Path.join(@root, "#{@baseline_dir}/requirement-statements-v1.json")

    case File.read(path) do
      {:ok, bytes} ->
        case Json.decode(bytes, Bounds.maximum()) do
          {:ok, tagged} -> plain(tagged)
          _ -> %{}
        end

      _ ->
        %{}
    end
  end

  # --- rule 5: cited counts re-derive from index.json --------------------------

  defp rule_5_cited_counts do
    live = live_applicability()

    Path.join(@root, @map_path)
    |> File.read!()
    |> then(&Regex.scan(~r/index\.json ([a-z_.]+)\.([a-z_]+)=(\d+)/, &1))
    |> Enum.flat_map(fn [_, surface, class, count] ->
      cited = String.to_integer(count)

      case live[surface][class] do
        nil ->
          ["rule 5: map cites #{surface}.#{class}=#{cited} but the live index has no such cell"]

        ^cited ->
          []

        actual ->
          ["rule 5: map cites #{surface}.#{class}=#{cited} but the live index counts #{actual}"]
      end
    end)
  end

  defp live_applicability do
    {:ok, bytes} = File.read(Path.join(@root, @index_path))
    {:ok, tagged} = Json.decode(bytes, Bounds.maximum())
    applicability = plain(tagged)["applicability"]

    Map.new(applicability, fn {surface, leaves} ->
      {surface,
       Map.new(leaves, fn
         {class, n} when is_integer(n) -> {class, n}
         {class, _n_a} -> {class, 0}
       end)}
    end)
  end

  # --- rule 6: revision citation ----------------------------------------------

  defp rule_6_revision_citation do
    map_text = Path.join(@root, @map_path) |> File.read!()

    with {:ok, revision} <- corpus_revision(),
         {:ok, cited} <- map_revision_line(map_text),
         :ok <- compare_revision(cited, revision) do
      []
    else
      {:error, reason} -> ["rule 6: #{reason}"]
    end
  end

  defp corpus_revision do
    path = Path.join(@root, @revision_path)

    with {:ok, bytes} <- File.read(path),
         {:ok, tagged} <- Json.decode(bytes, Bounds.maximum()) do
      case plain(tagged)["revision"] do
        revision when is_integer(revision) -> {:ok, revision}
        _ -> {:error, "revision.json carries no integer revision"}
      end
    else
      _ -> {:error, "cannot read the corpus revision integer from #{@revision_path}"}
    end
  end

  defp map_revision_line(text) do
    case Regex.run(~r/\*\*Corpus revision for every row:\*\* `(\d+)`/, text) do
      [_, cited] -> {:ok, String.to_integer(cited)}
      _ -> {:error, "requirement-map does not cite an integer corpus revision (the blanket line)"}
    end
  end

  defp compare_revision(cited, revision) when cited == revision, do: :ok

  defp compare_revision(cited, revision),
    do:
      {:error,
       "map cites corpus revision #{cited} but the corpus sidecar is at revision #{revision}"}

  # --- rule 9: vendor neutrality via tracked files ------------------------------

  defp rule_9_vendor_neutrality do
    files =
      @spec_docs ++
        [@map_path, @revision_path, @index_path] ++
        ["#{Path.dirname(@map_path)}/standards-track.md", "spec/tools/extract_facts.exs"]

    untracked =
      Enum.reject(files, fn file ->
        case System.cmd("git", ["ls-files", "--error-unmatch", file],
               cd: @root,
               stderr_to_stdout: true
             ) do
          {_out, 0} -> true
          _ -> false
        end
      end)

    privacy_present =
      File.exists?(Path.join(@root, "test/architecture/public_surface_privacy_test.exs")) and
        @root
        |> Path.join("test/architecture/public_surface_privacy_test.exs")
        |> File.read!()
        |> String.contains?("@forbidden_topology_hashes")

    problems =
      if privacy_present,
        do: [],
        else: [
          "rule 9: the public-surface privacy gate (ADR 0023 canary sweep) is missing — vendor neutrality is unenforced"
        ]

    problems ++
      Enum.map(untracked, fn file ->
        "rule 9: #{file} is not git-tracked — untracked authority files sit outside the privacy gate's full-tree canary sweep"
      end)
  end

  # --- rule 10: anchor completeness ---------------------------------------------

  defp rule_10_anchor_completeness(_facts) do
    protocol = Path.join(@root, "docs/protocol-v1.md") |> File.read!()

    adr =
      Path.join(
        @root,
        "docs/adr/0004-consumption-chain-rollover-and-anchored-export-verification.md"
      )
      |> File.read!()

    registries = Path.join(@root, "docs/design/registries.md") |> File.read!()

    # protocol-v1.md and ADR 0004: EVERY pipe-table row must sit inside an anchored region.
    uncovered =
      Enum.flat_map(
        [{"docs/protocol-v1.md", protocol}, {"docs/adr/0004", adr}],
        fn {name, doc} ->
          anchor_lines = anchor_line_numbers(doc)
          algebra_rows = algebra_row_numbers(doc)

          doc
          |> String.split("\n")
          |> Enum.with_index(1)
          |> Enum.filter(fn {line, _i} -> String.starts_with?(line, "|") end)
          |> Enum.reject(fn {_line, i} -> MapSet.member?(algebra_rows, i) end)
          |> Enum.reject(fn {line, _i} -> Regex.match?(~r/^\|[\s\-|:]+\|$/, line) end)
          |> Enum.flat_map(fn {_line, i} ->
            if Enum.any?(anchor_lines, fn {start, stop} -> i > start and i < stop end),
              do: [],
              else: ["#{name}:#{i}"]
          end)
          |> then(fn rows ->
            if rows == [],
              do: [],
              else: [
                "rule 10: #{name} has #{length(rows)} table-row(s) outside every anchored region (first at line #{hd(rows)})"
              ]
          end)
        end
      )

    # registries.md: only the typ table is a facts-owned table at this landing; its anchor must
    # sit directly above the table (rule 7 extends the registry sweep when the IANA templates land).
    typ_anchored =
      Regex.match?(~r/<!-- facts:typ-values -->\n\n?\| Value \| Status \| Purpose \|/, registries)

    typ_problem =
      if typ_anchored,
        do: [],
        else: ["rule 10: registries.md typ-values anchor does not sit on the typ table"]

    # docs/protocol-v1.md carries one pipe-table outside every anchored region BY DESIGN: the
    # JSON↔Elixir tagged-algebra binding table in "JSON algebra and decoding". Its facts are the
    # same tagged algebra the digest-constructions region extracts as the typed-projection table,
    # so rule 10 verifies that coverage (row-for-row) instead of trusting it.
    covered_problem =
      case Regex.run(~r/\| JSON \| Elixir value \|/, protocol) do
        nil ->
          [
            "rule 10: the JSON algebra binding table is missing from protocol-v1.md — the typed-projection facts are now unanchored"
          ]

        _ ->
          typed_rows = typed_projection_from_baseline()

          case typed_rows do
            nil ->
              ["rule 10: cannot read the typed-projection facts from the baseline"]

            _ ->
              algebra_tags = algebra_table_tags(protocol) |> Enum.map(&normalize_tag/1)
              projected_tags = Enum.map(typed_rows, &normalize_tag(&1["tagged"]))

              if Enum.sort(algebra_tags) == Enum.sort(projected_tags) do
                []
              else
                [
                  "rule 10: the JSON algebra table rows no longer match the typed-projection facts — an unanchored normative table diverged"
                ]
              end
          end
      end

    uncovered ++ typ_problem ++ covered_problem
  end

  # Both sides normalize to the base type name: the algebra table says "non-integer number"
  # where the tagged algebra says "{:float, value}" — same fact, different prose.
  defp normalize_tag("non-integer number"), do: "float"

  defp normalize_tag(tag) do
    tag
    |> String.replace_prefix(":", "")
    |> String.replace_prefix("{:", "")
    |> String.split([",", " ", "}"], trim: true)
    |> hd()
  end

  # Row labels from the algebra table's left column ("null", "boolean", ...).
  defp algebra_table_tags(protocol) do
    protocol
    |> String.split("\n")
    |> Enum.drop_while(fn line -> not String.starts_with?(line, "| JSON | Elixir value |") end)
    |> Enum.take_while(&String.starts_with?(&1, "|"))
    |> Enum.drop(2)
    |> Enum.map(fn row ->
      row |> String.trim_leading("|") |> String.split("|") |> hd() |> String.trim()
    end)
  end

  defp typed_projection_from_baseline do
    path = Path.join(@root, "#{@baseline_dir}/baseline-v1.json")

    case File.read(path) do
      {:ok, bytes} ->
        case Json.decode(bytes, Bounds.maximum()) do
          {:ok, tagged} ->
            case plain(tagged) do
              %{"digest-constructions" => %{"typed-projection" => rows}} when is_list(rows) ->
                rows

              _ ->
                nil
            end

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  # Line numbers of the one covered-elsewhere table (the JSON algebra binding table): rows from
  # its header through its last pipe row. Rule 10 verifies this table's coverage separately
  # against the typed-projection facts, so its rows are not "uncovered" — everything else is.
  defp algebra_row_numbers(doc) do
    lines = String.split(doc, "\n")

    case Enum.find_index(lines, &String.starts_with?(&1, "| JSON | Elixir value |")) do
      nil ->
        MapSet.new()

      start_index ->
        lines
        |> Enum.drop(start_index + 1)
        |> Enum.take_while(&String.starts_with?(&1, "|"))
        |> length()
        |> then(&MapSet.new((start_index + 1)..(start_index + 2 + &1)//1))
    end
  end

  defp anchor_line_numbers(doc) do
    lines = String.split(doc, "\n")

    anchors =
      lines
      |> Enum.with_index(1)
      |> Enum.filter(fn {line, _i} -> Regex.match?(~r/^<!-- facts:[a-z-]+ -->/, line) end)
      |> Enum.map(fn {_line, i} -> i end)

    stops =
      lines
      |> Enum.with_index(1)
      |> Enum.filter(fn {line, _i} ->
        String.starts_with?(line, "#") and not String.starts_with?(line, "###")
      end)
      |> Enum.map(&elem(&1, 1))

    Enum.map(anchors, fn start ->
      stop =
        case (stops ++ anchors) |> Enum.filter(&(&1 > start)) do
          [] -> start + 1_000_000
          later -> Enum.min(later)
        end

      {start, stop}
    end)
  end

  # --- shared -------------------------------------------------------------------

  defp plain({:object, members}),
    do: members |> Enum.map(fn {k, v} -> {k, plain(v)} end) |> Map.new()

  defp plain({:array, items}), do: Enum.map(items, &plain/1)
  defp plain({:string, s}), do: s
  defp plain({:integer, n}), do: n
  defp plain({:float, n}), do: n
  defp plain({:boolean, b}), do: b
  defp plain(:null), do: nil

  defp map_rows do
    Path.join(@root, @map_path)
    |> File.read!()
    |> String.split("\n")
    |> Enum.filter(&String.starts_with?(&1, "| REQ1-"))
    |> Enum.map(fn row ->
      row
      |> String.trim_leading("|")
      |> String.trim_trailing("|")
      |> String.split("|")
      |> Enum.map(&String.trim/1)
    end)
  end
end

BoundedAuthorityProtocol.SpecFactsGate.run()
