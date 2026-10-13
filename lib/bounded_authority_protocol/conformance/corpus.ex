defmodule BoundedAuthorityProtocol.Conformance.Corpus do
  @moduledoc """
  Pure loader and integrity verifier for the portable conformance corpus.

  `load/1` takes `%{path => binary}` (no I/O), decodes every `.json` file through
  `BoundedAuthorityProtocol.V1.Json.decode/2` at `Bounds.maximum()`, and verifies every
  corpus-integrity property named by the conformance contract:

  - per-file SHA-256 (`.json` and `.raw`) against the index,
  - exact file-set equality both directions,
  - per-file and total case counts,
  - corpus-wide case-id uniqueness,
  - applicability totality (every surface exactly 28, every class leaf exactly 16, required cells
    nonempty, `n_a` cells empty), and
  - tamper verbatim-vs-derived byte equality and `.raw` hash binding.

  `.raw` sidecars are hash-verified and carried as opaque binaries; they are never parsed.

  Every failure returns the fixed value-free `{:error, :invalid}`. The loaded corpus carries
  decoded cases, sidecar bytes, and the index for the runner and report.

  `load_strict_ed25519/1` loads the additive strict-Ed25519 corpus (profile
  `bap-strict-ed25519/1`), whose index has its own closed shape: per-file lowercase-hex SHA-256,
  per-file and per-family case counts, a profile and a revision sidecar, and no applicability
  matrix. The loaded corpus carries `major: :strict_ed25519`; each case names its own surface
  and, for v1/v2-shaped families, its own contract-major.
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json

  @enforce_keys [:index, :index_bytes, :cases, :raws, :case_ids, :major]
  defstruct [:index, :index_bytes, :cases, :raws, :case_ids, :major]

  @type t :: %__MODULE__{
          index: map(),
          index_bytes: binary(),
          cases: [{binary(), [map()]}],
          raws: %{binary() => binary()},
          case_ids: term(),
          major: 1 | 2 | 3 | :strict_ed25519
        }

  # The index format string names the corpus's contract-major; the loader derives
  # every other format constant (revision sidecar, case files) from it so a corpus
  # cannot mix materials across majors.
  @index_formats %{
    "bounded-authority-protocol-v1-conformance-corpus-index" => 1,
    "bounded-authority-protocol-v2-conformance-corpus-index" => 2,
    "bounded-authority-protocol-v3-conformance-corpus-index" => 3
  }
  @revision_formats %{
    1 => "bounded-authority-protocol-v1-conformance-corpus-revision",
    2 => "bounded-authority-protocol-v2-conformance-corpus-revision",
    3 => "bounded-authority-protocol-v3-conformance-corpus-revision"
  }
  @case_formats %{
    1 => "bounded-authority-protocol-v1-conformance-cases",
    2 => "bounded-authority-protocol-v2-conformance-cases",
    3 => "bounded-authority-protocol-v3-conformance-cases"
  }

  @doc "Loads and integrity-verifies a `%{path => binary}` corpus map."
  @spec load(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load(map) when is_map(map) do
    with {:ok, index_bytes} <- fetch_index(map),
         {:ok, index} <- decode_index(index_bytes),
         {:ok, major} <- verify_structure(index),
         {:ok, files} <- ordered_files(index),
         {:ok, cases, raws} <- load_files(files, map, major),
         :ok <- verify_file_set(files, map),
         :ok <- verify_hashes(files, map),
         :ok <- verify_counts(index, cases),
         :ok <- verify_case_ids(cases),
         :ok <- verify_applicability(index, cases),
         :ok <- verify_tampers(cases),
         :ok <- verify_raw_bindings(raws, cases) do
      case_ids = cases |> Enum.flat_map(&elem(&1, 1)) |> Enum.map(& &1["id"]) |> MapSet.new()

      {:ok,
       %__MODULE__{
         index: index,
         index_bytes: index_bytes,
         cases: cases,
         raws: raws,
         case_ids: case_ids,
         major: major
       }}
    end
  end

  def load(_map), do: {:error, :invalid}

  # --- strict-Ed25519 corpus -----------------------------------------------

  @strict_profile "bap-strict-ed25519/1"
  @strict_index_format "bounded-authority-protocol-strict-ed25519-conformance-corpus-index"
  @strict_case_format "bounded-authority-protocol-strict-ed25519-conformance-cases"
  @strict_profile_format "bounded-authority-protocol-strict-ed25519-conformance-profile"
  @strict_revision_format "bounded-authority-protocol-strict-ed25519-conformance-corpus-revision"
  @strict_sidecars ["profile.json", "revision.json"]

  @doc "Loads and integrity-verifies the `%{path => binary}` strict-Ed25519 corpus map."
  @spec load_strict_ed25519(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_strict_ed25519(map) when is_map(map) do
    with {:ok, index_bytes} <- fetch_index(map),
         {:ok, index} <- decode_index(index_bytes),
         :ok <- verify_strict_structure(index),
         {:ok, files} <- ordered_files(strict_file_entries(index["files"])),
         :ok <- verify_file_set(files, map),
         :ok <- verify_strict_hashes(files, map),
         :ok <- verify_strict_sidecars(map, index["revision"]),
         {:ok, cases} <- load_strict_case_files(files, map),
         :ok <- verify_strict_counts(index, files, cases),
         :ok <- verify_case_ids(cases) do
      case_ids = cases |> Enum.flat_map(&elem(&1, 1)) |> Enum.map(& &1["id"]) |> MapSet.new()

      {:ok,
       %__MODULE__{
         index: index,
         index_bytes: index_bytes,
         cases: cases,
         raws: %{},
         case_ids: case_ids,
         major: :strict_ed25519
       }}
    end
  end

  def load_strict_ed25519(_map), do: {:error, :invalid}

  defp verify_strict_structure(index) do
    if index["format"] == @strict_index_format and index["profile"] == @strict_profile and
         revision_integer?({:integer, index["revision"]}) and
         index["private_material_tracked"] == false and is_list(index["files"]) and
         is_integer(index["total_cases"]) and is_map(index["families"]),
       do: :ok,
       else: {:error, :invalid}
  end

  # The strict index names each file's digest as lowercase hex under "sha256"; mapping it onto
  # the shared {path, hash, count} tuple reuses the ordered-file and file-set checks unchanged.
  defp strict_file_entries(entries) when is_list(entries) do
    %{
      "files" =>
        Enum.map(entries, fn
          %{"path" => path, "sha256" => hash, "cases" => count} ->
            %{"path" => path, "sha256_base64url" => hash, "cases" => count}

          _invalid ->
            :invalid
        end)
    }
  end

  defp verify_strict_hashes(files, map) do
    if Enum.all?(files, fn {path, hash, _count} -> strict_hash_matches?(map, path, hash) end),
      do: :ok,
      else: {:error, :invalid}
  end

  defp strict_hash_matches?(map, path, hash) do
    case fetch_path(map, path) do
      {:ok, bytes} -> sha256_hex(bytes) == hash
      _missing -> false
    end
  end

  defp verify_strict_sidecars(map, revision) do
    with {:ok, profile} <- decode_plain(map, "profile.json"),
         {:ok, sidecar} <- decode_plain(map, "revision.json"),
         true <- profile["format"] == @strict_profile_format,
         true <- profile["profile"] == @strict_profile,
         true <- profile["revision"] == revision,
         true <- sidecar["format"] == @strict_revision_format,
         true <- sidecar["revision"] == revision,
         true <- generated_from_string?({:string, sidecar["generated_from"]}) do
      :ok
    else
      _invalid -> {:error, :invalid}
    end
  end

  # Every non-sidecar file is cases/<family>/<name>.json, carries the case format, names its
  # own directory as its family, and holds a list of case objects that each name a surface.
  defp load_strict_case_files(files, map) do
    loaded =
      files
      |> Enum.reject(fn {path, _hash, _count} -> path in @strict_sidecars end)
      |> Enum.map(fn {path, _hash, _count} -> {path, load_strict_case_file(path, map)} end)

    if Enum.all?(loaded, &match?({_path, {:ok, _cases}}, &1)),
      do: {:ok, Enum.map(loaded, fn {path, {:ok, cases}} -> {path, cases} end)},
      else: {:error, :invalid}
  end

  defp load_strict_case_file(path, map) do
    with ["cases", family, name] <- String.split(path, "/"),
         true <- String.ends_with?(name, ".json"),
         {:ok, file} <- decode_plain(map, path),
         true <- file["format"] == @strict_case_format,
         true <- file["family"] == family,
         cases when is_list(cases) and cases != [] <- file["cases"],
         true <- Enum.all?(cases, &strict_case?/1) do
      {:ok, Enum.map(cases, &Map.put(&1, "family", family))}
    else
      _invalid -> :error
    end
  end

  defp strict_case?(%{"id" => id, "surface" => surface})
       when is_binary(id) and is_binary(surface),
       do: true

  defp strict_case?(_case_obj), do: false

  defp verify_strict_counts(index, files, cases) do
    per_file = Map.new(cases, fn {path, list} -> {path, length(list)} end)

    files_agree? =
      Enum.all?(files, fn {path, _hash, count} ->
        if path in @strict_sidecars, do: count == 0, else: Map.get(per_file, path) == count
      end)

    per_family =
      cases
      |> Enum.flat_map(&elem(&1, 1))
      |> Enum.reduce(%{}, fn case_obj, acc ->
        Map.update(acc, case_obj["family"], 1, &(&1 + 1))
      end)

    total = Enum.reduce(cases, 0, fn {_path, list}, acc -> acc + length(list) end)

    if files_agree? and per_family == index["families"] and total == index["total_cases"],
      do: :ok,
      else: {:error, :invalid}
  end

  defp decode_plain(map, path) do
    with {:ok, bytes} <- fetch_path(map, path),
         {:ok, {:object, _members} = value} <- Json.decode(bytes, Bounds.maximum()) do
      {:ok, to_plain(value)}
    else
      _invalid -> {:error, :invalid}
    end
  end

  defp sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  # --- index decoding ------------------------------------------------------

  defp fetch_index(map) do
    case Map.get(map, "index.json") do
      bytes when is_binary(bytes) -> {:ok, bytes}
      _ -> {:error, :invalid}
    end
  end

  defp decode_index(bytes) do
    case Json.decode(bytes, Bounds.maximum()) do
      {:ok, {:object, _members} = value} -> {:ok, to_plain(value)}
      _ -> {:error, :invalid}
    end
  end

  defp verify_structure(%{"format" => format} = index) do
    case Map.fetch(@index_formats, format) do
      {:ok, major} ->
        cond do
          not is_list(index["files"]) -> {:error, :invalid}
          not is_list(index["public_key_fingerprints"]) -> {:error, :invalid}
          not is_integer(index["total_cases"]) -> {:error, :invalid}
          not is_map(index["applicability"]) -> {:error, :invalid}
          true -> {:ok, major}
        end

      :error ->
        {:error, :invalid}
    end
  end

  defp verify_structure(_index), do: {:error, :invalid}

  defp ordered_files(%{"files" => files}) do
    result =
      Enum.reduce_while(files, {:ok, []}, fn entry, {:ok, acc} ->
        case file_entry_tuple(entry) do
          {:ok, tuple} -> {:cont, {:ok, [tuple | acc]}}
          :error -> {:halt, {:error, :invalid}}
        end
      end)

    case result do
      {:ok, entries} -> {:ok, Enum.sort_by(entries, &elem(&1, 0))}
      error -> error
    end
  end

  defp file_entry_tuple(%{"path" => path, "sha256_base64url" => hash, "cases" => count})
       when is_binary(path) and is_binary(hash) and is_integer(count),
       do: {:ok, {path, hash, count}}

  defp file_entry_tuple(_entry), do: :error

  # --- file loading --------------------------------------------------------

  defp load_files(files, map, major) do
    Enum.reduce_while(files, {:ok, [], %{}}, fn {path, hash, _count}, {:ok, cases, raws} ->
      load_one_file(path, hash, map, major, cases, raws)
    end)
  end

  # The revision sidecar occupies the one reserved non-case path in the files set. It is
  # fetched (missing → invalid) and shape-validated here; its SHA-256 is enforced by the same
  # generic per-file pass as every other declared file, and its file-set membership by
  # verify_file_set. It contributes no cases and is not carried on the loaded corpus.
  defp load_one_file("revision.json" = path, _hash, map, major, cases, raws) do
    case fetch_path(map, path) do
      {:ok, bytes} ->
        if valid_revision_sidecar?(bytes, major),
          do: {:cont, {:ok, cases, raws}},
          else: {:halt, {:error, :invalid}}

      _ ->
        {:halt, {:error, :invalid}}
    end
  end

  defp load_one_file(path, hash, map, major, cases, raws) do
    cond do
      String.ends_with?(path, ".json") ->
        load_json_entry(map, path, major, cases, raws)

      String.ends_with?(path, ".raw") ->
        load_raw_entry(map, path, hash, cases, raws)

      true ->
        {:halt, {:error, :invalid}}
    end
  end

  # Closed 3-member shape: exactly {format, revision, generated_from}, the major's format
  # const, a monotone integer revision (1..integer_magnitude), and a non-empty bounded
  # provenance string. A self-consistent sidecar of any other shape fails closed — the
  # per-file hash cannot catch a sidecar that was rewritten together with its index entry.
  defp valid_revision_sidecar?(bytes, major) do
    case Json.decode(bytes, Bounds.maximum()) do
      {:ok, {:object, members}} ->
        keys = Enum.map(members, &elem(&1, 0))

        # Exact-member-set check without Enum.sort (forbidden in this module by the
        # architecture gate): 3 keys whose difference with the closed set is empty both ways.
        length(keys) == 3 and keys -- ["format", "generated_from", "revision"] == [] and
          member(members, "format") == {:string, Map.get(@revision_formats, major)} and
          revision_integer?(member(members, "revision")) and
          generated_from_string?(member(members, "generated_from"))

      _ ->
        false
    end
  end

  defp revision_integer?({:integer, n}), do: n >= 1 and n <= 9_007_199_254_740_991
  defp revision_integer?(_), do: false

  defp generated_from_string?({:string, source}),
    do: byte_size(source) >= 1 and byte_size(source) <= 256

  defp generated_from_string?(_), do: false

  defp load_json_entry(map, path, major, cases, raws) do
    case load_json_file(map, path, major) do
      {:ok, decoded} -> {:cont, {:ok, [{path, decoded} | cases], raws}}
      :error -> {:halt, {:error, :invalid}}
    end
  end

  defp load_raw_entry(map, path, hash, cases, raws) do
    case fetch_path(map, path) do
      {:ok, bytes} -> {:cont, {:ok, cases, Map.put(raws, path, {bytes, hash})}}
      _ -> {:halt, {:error, :invalid}}
    end
  end

  defp load_json_file(map, path, major) do
    with {:ok, bytes} <- fetch_path(map, path),
         {:ok, decoded} <- decode_case_file(bytes, major) do
      {:ok, decoded}
    else
      _ -> :error
    end
  end

  defp fetch_path(map, path) do
    case Map.get(map, path) do
      bytes when is_binary(bytes) -> {:ok, bytes}
      _ -> {:error, :invalid}
    end
  end

  defp decode_case_file(bytes, major) do
    case Json.decode(bytes, Bounds.maximum()) do
      {:ok, value} ->
        with {:object, members} <- value,
             {:string, format} <- member(members, "format"),
             true <- format == Map.get(@case_formats, major),
             {:array, items} <- member(members, "cases") do
          {:ok, Enum.map(items, &to_plain/1)}
        else
          _ -> {:error, :invalid}
        end

      _ ->
        {:error, :invalid}
    end
  end

  # --- file-set equality both directions -----------------------------------

  defp verify_file_set(files, map) do
    declared = files |> Enum.map(&elem(&1, 0)) |> MapSet.new()

    present =
      map
      |> Map.keys()
      |> Enum.reject(&(&1 == "index.json"))
      |> MapSet.new()

    if MapSet.equal?(declared, present),
      do: :ok,
      else: {:error, :invalid}
  end

  # --- per-file SHA-256 ----------------------------------------------------

  defp verify_hashes(files, map) do
    Enum.reduce_while(files, :ok, fn {path, hash, _count}, :ok ->
      with {:ok, bytes} <- fetch_path(map, path),
           true <- sha256_b64(bytes) == hash do
        {:cont, :ok}
      else
        _ -> {:halt, {:error, :invalid}}
      end
    end)
  end

  # --- counts --------------------------------------------------------------

  defp verify_counts(%{"total_cases" => total, "files" => files}, cases) do
    per_file_sums =
      cases
      |> Enum.map(fn {path, list} -> {path, length(list)} end)
      |> Map.new()

    declared_total =
      Enum.reduce_while(files, {:ok, 0}, fn %{"path" => path, "cases" => count}, {:ok, acc} ->
        case {observed_file_count(per_file_sums, path), String.ends_with?(path, ".raw"), count,
              path} do
          {observed, false, _, _} when observed != :absent and observed == count ->
            {:cont, {:ok, acc + count}}

          # .raw sidecars carry no cases; their declared count must be 0.
          {:absent, true, 0, _} ->
            {:cont, {:ok, acc}}

          # The revision sidecar (reserved root path only) is likewise case-free.
          {:absent, false, 0, "revision.json"} ->
            {:cont, {:ok, acc}}

          _ ->
            {:halt, {:error, :invalid}}
        end
      end)

    case declared_total do
      {:ok, ^total} -> :ok
      _ -> {:error, :invalid}
    end
  end

  defp observed_file_count(per_file_sums, path) do
    case Map.fetch(per_file_sums, path) do
      {:ok, count} -> count
      :error -> :absent
    end
  end

  # --- case-id uniqueness --------------------------------------------------

  defp verify_case_ids(cases) do
    all_ids = cases |> Enum.flat_map(&elem(&1, 1)) |> Enum.map(& &1["id"])

    if length(all_ids) == MapSet.size(MapSet.new(all_ids)) and Enum.all?(all_ids, &is_binary/1),
      do: :ok,
      else: {:error, :invalid}
  end

  # --- applicability totality ----------------------------------------------

  defp verify_applicability(%{"applicability" => applicability}, cases) do
    with :ok <- verify_applicability_shape(applicability),
         observed <- observed_counts(cases) do
      if applicability_matches?(applicability, observed), do: :ok, else: {:error, :invalid}
    end
  end

  defp verify_applicability_shape(applicability) do
    surfaces = corpus_surfaces()
    classes = corpus_classes()

    surface_ok? =
      MapSet.equal?(MapSet.new(Map.keys(applicability)), MapSet.new(surfaces)) and
        Enum.all?(surfaces, fn surface ->
          leaves = Map.get(applicability, surface)
          is_map(leaves) and MapSet.equal?(MapSet.new(Map.keys(leaves)), MapSet.new(classes))
        end)

    if surface_ok?, do: :ok, else: {:error, :invalid}
  end

  defp observed_counts(cases) do
    cases
    |> Enum.flat_map(&elem(&1, 1))
    |> Enum.reduce(%{}, &count_surface_class/2)
  end

  defp count_surface_class(case_obj, acc) do
    surface = case_obj["surface"]
    class = case_obj["class"]

    if is_binary(surface) and is_binary(class) do
      increment_leaf(acc, surface, class)
    else
      acc
    end
  end

  defp increment_leaf(acc, surface, class) do
    surface_leaves = Map.get(acc, surface, %{})
    updated = Map.update(surface_leaves, class, 1, &(&1 + 1))
    Map.put(acc, surface, updated)
  end

  defp applicability_matches?(applicability, observed) do
    Enum.all?(corpus_surfaces(), fn surface ->
      surface_matches?(applicability, observed, surface)
    end)
  end

  defp surface_matches?(applicability, observed, surface) do
    declared = Map.fetch!(applicability, surface)
    observed_surface = Map.get(observed, surface, %{})

    Enum.all?(corpus_classes(), fn class ->
      leaf_matches?(declared, observed_surface, class)
    end)
  end

  defp leaf_matches?(declared, observed_surface, class) do
    declared_leaf = Map.fetch!(declared, class)
    observed_count = Map.get(observed_surface, class, 0)

    case declared_leaf do
      n when is_integer(n) and n >= 1 -> observed_count == n
      "n_a" -> observed_count == 0
      # An applicability leaf may carry a falsifiable reason: {"n_a": "<reason>"}. The reason
      # is for human review (Q29 obligation), not machine logic — treated identically to the
      # bare "n_a" string (not-applicable: zero executed cases).
      %{"n_a" => _reason} -> observed_count == 0
      _ -> false
    end
  end

  # --- tamper verbatim-vs-derived (Q25) ------------------------------------

  defp verify_tampers(cases) do
    all = cases |> Enum.flat_map(&elem(&1, 1))
    by_id = Map.new(all, &{&1["id"], &1})

    Enum.reduce_while(all, :ok, fn case_obj, :ok ->
      case check_one_tamper(case_obj, by_id) do
        :ok -> {:cont, :ok}
        :invalid -> {:halt, {:error, :invalid}}
      end
    end)
  end

  defp check_one_tamper(%{"tamper" => tamper} = case_obj, by_id) do
    with %{"base_case" => base_id, "byte_index" => index, "xor" => xor}
         when is_integer(index) and is_integer(xor) <- tamper,
         %{} = base <- Map.get(by_id, base_id) do
      target = Map.get(tamper, "target")
      if tamper_verbatim_matches?(case_obj, base, target, index, xor), do: :ok, else: :invalid
    else
      # A PRESENT tamper block that is malformed (non-integer byte_index/xor) or references a
      # missing base_case is a corrupt corpus — reject, matching the independent Node audit
      # (which asserts base present + integer byte_index/xor). Only a case with NO tamper block is
      # a non-tamper case (the second clause) and passes this check untouched.
      _ -> :invalid
    end
  end

  defp check_one_tamper(_case_obj, _by_id), do: :ok

  defp tamper_verbatim_matches?(case_obj, base, target, index, xor) do
    with {:ok, base_bytes} <- tamper_target_bytes(base, target),
         {:ok, verbatim_bytes} <- tamper_target_bytes(case_obj, target) do
      derived = derive_tampered_bytes(base_bytes, index, xor)
      derived == verbatim_bytes
    else
      _ -> false
    end
  end

  # Re-derive the FULL tampered bytes from the base case: the base with the single
  # documented byte flipped by xor. The verbatim artifact must byte-equal this
  # (design Q25) — not just match at the one index.
  defp derive_tampered_bytes(base_bytes, index, xor) do
    size = byte_size(base_bytes)

    if index >= 0 and index < size do
      <<pre::binary-size(^index), byte, post::binary>> = base_bytes
      pre <> <<Bitwise.bxor(byte, xor)>> <> post
    else
      :error
    end
  end

  # Resolve the bytes a tamper's verbatim-vs-derived audit binds to, per the tamper `target`.
  # Both the base case's source bytes and the tampered case's verbatim bytes resolve through the
  # SAME target, so the audit re-derives base-with-one-flip and byte-compares against the stored
  # verbatim on exactly the addressed artifact. The default/`"input.text"`/`"input.base64url"`
  # paths preserve the original text/base64url resolution (back-compat); the extended targets
  # address the byte-bearing verifying-surface inputs: the compact JWS string (`"compact"`), a
  # named compact inside a check_envelope input (`"grant"`/`"proof"`), or the decoded i-th
  # base64url row/chunk (`"rows[i]"`/`"chunks[i]"`) of a chain/archive input.
  defp tamper_target_bytes(%{"input" => input}, target) do
    case target do
      nil -> legacy_target_bytes(input)
      "input.text" -> text_target_bytes(input)
      "input.base64url" -> b64_target_bytes(input, "base64url")
      t when t in ["compact", "grant", "proof"] -> string_target_bytes(input, t)
      "rows[" <> suffix -> indexed_target_bytes(input["rows"], suffix)
      "chunks[" <> suffix -> indexed_target_bytes(input["chunks"], suffix)
      _ -> :error
    end
  end

  defp tamper_target_bytes(_case_obj, _target), do: :error

  defp legacy_target_bytes(input) do
    cond do
      is_binary(input["text"]) -> {:ok, input["text"]}
      is_binary(input["base64url"]) -> b64_decode(input["base64url"])
      true -> :error
    end
  end

  defp text_target_bytes(input) do
    if is_binary(input["text"]), do: {:ok, input["text"]}, else: :error
  end

  defp string_target_bytes(input, key) do
    if is_binary(input[key]), do: {:ok, input[key]}, else: :error
  end

  defp b64_target_bytes(input, key) do
    if is_binary(input[key]), do: b64_decode(input[key]), else: :error
  end

  # Resolve `key[i]` to the decoded i-th base64url element of `list`. The index is parsed from the
  # `i]` suffix with a pure digit fold (Regex/Integer/Enum.at are forbidden in this module by the
  # architecture gate), and the element is fetched by recursive list walk.
  defp indexed_target_bytes(list, suffix) when is_list(list) do
    with {:ok, i} <- parse_index_suffix(suffix, 0, false),
         {:ok, element} when is_binary(element) <- list_at(list, i) do
      b64_decode(element)
    else
      _ -> :error
    end
  end

  defp indexed_target_bytes(_list, _suffix), do: :error

  defp parse_index_suffix(<<d, rest::binary>>, acc, _seen) when d >= ?0 and d <= ?9,
    do: parse_index_suffix(rest, acc * 10 + (d - ?0), true)

  defp parse_index_suffix("]", acc, true), do: {:ok, acc}
  defp parse_index_suffix(_suffix, _acc, _seen), do: :error

  defp list_at([element | _rest], 0), do: {:ok, element}
  defp list_at([_element | rest], i) when i > 0, do: list_at(rest, i - 1)
  defp list_at(_list, _i), do: :error

  defp b64_decode(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> :error
    end
  end

  # --- .raw hash binding ---------------------------------------------------

  defp verify_raw_bindings(raws, cases) do
    cases
    |> Enum.flat_map(&elem(&1, 1))
    |> Enum.reduce(:ok, &check_raw_binding(&1, raws, &2))
  end

  defp check_raw_binding(case_obj, raws, :ok) do
    with %{"input" => input} <- case_obj,
         %{"raw_file" => raw_path, "sha256_base64url" => hash} <- input do
      verify_raw_entry(raws, raw_path, hash)
    else
      _ -> :ok
    end
  end

  defp check_raw_binding(_case_obj, _raws, error), do: error

  defp verify_raw_entry(raws, raw_path, hash) do
    case Map.get(raws, raw_path) do
      {bytes, index_hash} ->
        if sha256_b64(bytes) == hash and hash == index_hash,
          do: :ok,
          else: {:error, :invalid}

      _ ->
        {:error, :invalid}
    end
  end

  # --- tagged-algebra → plain-value projection -----------------------------

  defp to_plain({:object, members}),
    do: members |> Enum.map(fn {k, v} -> {k, to_plain(v)} end) |> Map.new()

  defp to_plain({:array, items}), do: Enum.map(items, &to_plain/1)
  defp to_plain({:string, s}), do: s
  defp to_plain({:integer, n}), do: n
  defp to_plain({:float, n}), do: n
  defp to_plain({:boolean, b}), do: b
  defp to_plain(:null), do: nil

  defp member(members, key) do
    case List.keyfind(members, key, 0) do
      {^key, value} -> value
      nil -> nil
    end
  end

  defp sha256_b64(bytes), do: Base.url_encode64(:crypto.hash(:sha256, bytes), padding: false)

  defp corpus_surfaces do
    [
      "untrusted_key_locator",
      "grant_signing_input",
      "proof_signing_input",
      "encode_consumption_entry",
      "check_chain",
      "boundary_anchor_signing_input",
      "key_transition_signing_input",
      "encode_anchored_export",
      "assemble_compact",
      "decode_grant",
      "decode_proof",
      "verify_grant",
      "verify_historical_anchor",
      "verify_key_transition",
      "verify_anchored_export",
      "check_envelope",
      "request_digest",
      "jcs.encode",
      "jwk.encode_public",
      "jwk.decode_public",
      "jwk.thumbprint_preimage",
      "jwk.thumbprint",
      "jwk.thumbprint_raw",
      "jwk.public_key_thumbprint_raw",
      "uri.normalize",
      "json.decode",
      "base64url.decode",
      "bounds.new"
    ]
  end

  defp corpus_classes do
    [
      "valid",
      "boundary_near",
      "exact_bound",
      "maximum_plus_one",
      "invalid_duplicate",
      "invalid_encoding",
      "invalid_algorithm",
      "invalid_key",
      "invalid_claim",
      "invalid_time",
      "invalid_nonce",
      "invalid_uri",
      "invalid_request",
      "invalid_selector",
      "invalid_limit",
      "tamper_meaningful_byte"
    ]
  end
end
