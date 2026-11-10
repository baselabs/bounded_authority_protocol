defmodule BoundedAuthorityProtocol.Conformance.Corpus do
  @moduledoc false

  # Internal to the conformance CLI (not public API). Pure loader and integrity verifier for the
  # portable conformance corpora. Every loader takes `%{path => binary}` (no I/O), decodes every
  # `.json` file through `V1.Json.decode/2` at `Bounds.maximum()`, verifies the corpus's own
  # integrity properties, and returns the fixed value-free `{:error, :invalid}` on any failure.
  #
  # - `load/1`: a contract-major corpus (v1, v2, v3). Per-file SHA-256 (`.json` and `.raw`)
  #   against the index, exact file-set equality, per-file and total case counts, corpus-wide
  #   case-id uniqueness, applicability totality (every surface 28, every class leaf 16, required
  #   cells nonempty, `n_a` cells empty), tamper verbatim-vs-derived byte equality and `.raw`
  #   hash binding. `.raw` sidecars are hash-verified and carried opaque.
  # - `load_strict_ed25519/1`, `load_producer_canonicality/1`, `load_selector_float_zero/1`: the
  #   additive corpora, which share one closed index shape (per-file lowercase-hex SHA-256,
  #   per-file and per-family counts, profile and revision sidecars, no applicability matrix).
  # - `load_local_loopback_http/1`, `load_role_attestation/1`, `load_content_assertion/1`: the
  #   sibling-profile corpora, each with its own closed index (an exact ordered file list with
  #   lowercase-hex SHA-256 and per-kind case counts) and a `profile.json` the runner reads.
  #
  # `total_cases` is the census the CLI requires the runner to execute exactly: the index's
  # `total_cases` for contract-major and additive corpora, the sum of the declared per-kind counts
  # for sibling corpora (plus the local-loopback profile's certified proofs, which run as cases).

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json

  @enforce_keys [:index, :index_bytes, :cases, :raws, :case_ids, :major]
  defstruct [
    :index,
    :index_bytes,
    :cases,
    :raws,
    :case_ids,
    :major,
    profile: nil,
    total_cases: nil
  ]

  @type t :: %__MODULE__{
          index: map(),
          index_bytes: binary(),
          cases: [{binary(), [map()]}],
          raws: %{binary() => binary()},
          case_ids: term(),
          major:
            1
            | 2
            | 3
            | :strict_ed25519
            | :producer_canonicality
            | :selector_float_zero
            | :local_loopback_http
            | :role_attestation
            | :content_assertion,
          profile: map() | nil,
          total_cases: non_neg_integer() | nil
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
         major: major,
         total_cases: index["total_cases"]
       }}
    end
  end

  def load(_map), do: {:error, :invalid}

  @doc """
  Loads `map` with whichever loader accepts its index. Each loader accepts only its own index
  format, so at most one can succeed; all fail closed.
  """
  @spec load_any(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_any(map) do
    with {:error, :invalid} <- load(map),
         {:error, :invalid} <- load_strict_ed25519(map),
         {:error, :invalid} <- load_producer_canonicality(map),
         {:error, :invalid} <- load_selector_float_zero(map),
         {:error, :invalid} <- load_local_loopback_http(map),
         {:error, :invalid} <- load_role_attestation(map) do
      load_content_assertion(map)
    end
  end

  @doc """
  The relative paths an index names, for the CLI to read and nothing else. Every path must be a
  plain relative path: forward-slash segments, none empty, `.` or `..`, no backslash or NUL, and
  never `index.json` itself. Duplicates are invalid.
  """
  @spec declared_paths(binary()) :: {:ok, [binary()]} | {:error, :invalid}
  def declared_paths(index_bytes) when is_binary(index_bytes) do
    with {:ok, %{"files" => files}} when is_list(files) <- decode_index(index_bytes),
         {:ok, paths} <- collect_paths(files),
         true <- length(paths) == MapSet.size(MapSet.new(paths)) do
      {:ok, paths}
    else
      _invalid -> {:error, :invalid}
    end
  end

  def declared_paths(_index_bytes), do: {:error, :invalid}

  @doc """
  `:ok` when every present path is `index.json` or a declared path; the CLI refuses a corpus
  directory holding any file the index does not name.
  """
  @spec only_declared(present :: [binary()], declared :: [binary()]) :: :ok | {:error, :invalid}
  def only_declared(present, declared) do
    if present -- ["index.json" | declared] == [],
      do: :ok,
      else: {:error, :invalid}
  end

  @doc """
  True when `results` are exactly the loaded census: unique case ids, the same id set as the
  corpus, `total_cases` of them, and each under the file that declared it. The report requires
  it for agreement.
  """
  @spec complete?(t(), [{binary(), [%{case_id: binary(), agree: boolean()}]}]) :: boolean()
  def complete?(%__MODULE__{cases: cases, case_ids: case_ids, total_cases: total}, results)
      when is_list(results) do
    declared =
      cases
      |> Enum.flat_map(fn {path, list} -> Enum.map(list, &{&1["id"], path}) end)
      |> Map.new()

    executed =
      Enum.flat_map(results, fn {path, list} ->
        Enum.map(list, fn %{case_id: id} -> {id, path} end)
      end)

    unique = executed |> Enum.map(&elem(&1, 0)) |> MapSet.new()

    length(executed) == total and MapSet.size(unique) == total and
      MapSet.equal?(unique, case_ids) and
      Enum.all?(executed, fn {id, path} -> Map.get(declared, id) == path end)
  end

  defp collect_paths(files) do
    paths = Enum.map(files, &declared_path/1)
    if Enum.all?(paths, &is_binary/1), do: {:ok, paths}, else: :error
  end

  defp declared_path(%{"path" => path}) when is_binary(path) do
    if path == "index.json" or not String.valid?(path) or
         not Enum.all?(String.split(path, "/"), &safe_segment?/1),
       do: :invalid,
       else: path
  end

  defp declared_path(_entry), do: :invalid

  defp safe_segment?(""), do: false
  defp safe_segment?("."), do: false
  defp safe_segment?(".."), do: false
  defp safe_segment?(segment), do: plain_bytes?(segment)

  # No backslash (a Windows separator) and no NUL inside a segment.
  defp plain_bytes?(<<>>), do: true
  defp plain_bytes?(<<?\\, _rest::binary>>), do: false
  defp plain_bytes?(<<0, _rest::binary>>), do: false
  defp plain_bytes?(<<_byte, rest::binary>>), do: plain_bytes?(rest)

  # --- additive corpora (strict-Ed25519, producer-canonicality) -------------

  # The two additive corpora share one closed index shape: per-file lowercase-hex SHA-256,
  # per-file and per-family case counts, a profile and a revision sidecar, and no applicability
  # matrix. Each carries its own profile and format strings, so a loader accepts only its own.
  @strict_ed25519 %{
    major: :strict_ed25519,
    profile: "bap-strict-ed25519/1",
    index_format: "bounded-authority-protocol-strict-ed25519-conformance-corpus-index",
    case_format: "bounded-authority-protocol-strict-ed25519-conformance-cases",
    profile_format: "bounded-authority-protocol-strict-ed25519-conformance-profile",
    revision_format: "bounded-authority-protocol-strict-ed25519-conformance-corpus-revision"
  }

  @producer_canonicality %{
    major: :producer_canonicality,
    profile: "bap-producer-canonicality/1",
    index_format: "bounded-authority-protocol-producer-canonicality-conformance-corpus-index",
    case_format: "bounded-authority-protocol-producer-canonicality-conformance-cases",
    profile_format: "bounded-authority-protocol-producer-canonicality-conformance-profile",
    revision_format:
      "bounded-authority-protocol-producer-canonicality-conformance-corpus-revision"
  }

  @selector_float_zero %{
    major: :selector_float_zero,
    profile: "bap-selector-float-zero/1",
    index_format: "bounded-authority-protocol-selector-float-zero-conformance-corpus-index",
    case_format: "bounded-authority-protocol-selector-float-zero-conformance-cases",
    profile_format: "bounded-authority-protocol-selector-float-zero-conformance-profile",
    revision_format: "bounded-authority-protocol-selector-float-zero-conformance-corpus-revision"
  }

  @additive_sidecars ["profile.json", "revision.json"]

  # One clause per sidecar: `in` over a list of binaries compiles to :lists.member/2 on
  # Elixir before 1.20, which the compiled-purity gate does not admit.
  for sidecar <- @additive_sidecars do
    defp additive_sidecar?(unquote(sidecar)), do: true
  end

  defp additive_sidecar?(_path), do: false

  @doc "Loads and integrity-verifies the `%{path => binary}` strict-Ed25519 corpus map."
  @spec load_strict_ed25519(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_strict_ed25519(map) when is_map(map), do: load_additive(map, @strict_ed25519)
  def load_strict_ed25519(_map), do: {:error, :invalid}

  @doc """
  Loads and integrity-verifies the `%{path => binary}` producer-canonicality corpus map (profile
  `bap-producer-canonicality/1`, erratum 3). The loaded corpus carries
  `major: :producer_canonicality`; each case names its own contract-major or sibling profile.
  """
  @spec load_producer_canonicality(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_producer_canonicality(map) when is_map(map),
    do: load_additive(map, @producer_canonicality)

  def load_producer_canonicality(_map), do: {:error, :invalid}

  @doc """
  Loads and integrity-verifies the `%{path => binary}` selector float-zero corpus map (profile
  `bap-selector-float-zero/1`, erratum 6). The loaded corpus carries `major: :selector_float_zero`;
  each case names its own contract-major.
  """
  @spec load_selector_float_zero(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_selector_float_zero(map) when is_map(map),
    do: load_additive(map, @selector_float_zero)

  def load_selector_float_zero(_map), do: {:error, :invalid}

  defp load_additive(map, %{major: major} = spec) do
    with {:ok, index_bytes} <- fetch_index(map),
         {:ok, index} <- decode_index(index_bytes),
         :ok <- verify_additive_structure(index, spec),
         {:ok, files} <- ordered_files(additive_file_entries(index["files"])),
         :ok <- verify_file_set(files, map),
         :ok <- verify_additive_hashes(files, map),
         :ok <- verify_additive_sidecars(map, index["revision"], spec),
         {:ok, cases} <- load_additive_case_files(files, map, spec),
         :ok <- verify_additive_counts(index, files, cases),
         :ok <- verify_case_ids(cases) do
      case_ids = cases |> Enum.flat_map(&elem(&1, 1)) |> Enum.map(& &1["id"]) |> MapSet.new()

      {:ok,
       %__MODULE__{
         index: index,
         index_bytes: index_bytes,
         cases: cases,
         raws: %{},
         case_ids: case_ids,
         major: major,
         total_cases: index["total_cases"]
       }}
    end
  end

  defp verify_additive_structure(index, %{index_format: index_format, profile: profile}) do
    if index["format"] == index_format and index["profile"] == profile and
         revision_integer?({:integer, index["revision"]}) and
         index["private_material_tracked"] == false and is_list(index["files"]) and
         is_integer(index["total_cases"]) and is_map(index["families"]),
       do: :ok,
       else: {:error, :invalid}
  end

  # The additive index names each file's digest as lowercase hex under "sha256"; mapping it onto
  # the shared {path, hash, count} tuple reuses the ordered-file and file-set checks unchanged.
  defp additive_file_entries(entries) when is_list(entries) do
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

  defp verify_additive_hashes(files, map) do
    if Enum.all?(files, fn {path, hash, _count} -> additive_hash_matches?(map, path, hash) end),
      do: :ok,
      else: {:error, :invalid}
  end

  defp additive_hash_matches?(map, path, hash) do
    case fetch_path(map, path) do
      {:ok, bytes} -> sha256_hex(bytes) == hash
      _missing -> false
    end
  end

  defp verify_additive_sidecars(map, revision, %{
         profile: profile_name,
         profile_format: profile_format,
         revision_format: revision_format
       }) do
    with {:ok, profile} <- decode_plain(map, "profile.json"),
         {:ok, sidecar} <- decode_plain(map, "revision.json"),
         true <- profile["format"] == profile_format,
         true <- profile["profile"] == profile_name,
         true <- profile["revision"] == revision,
         true <- sidecar["format"] == revision_format,
         true <- sidecar["revision"] == revision,
         true <- generated_from_string?({:string, sidecar["generated_from"]}) do
      :ok
    else
      _invalid -> {:error, :invalid}
    end
  end

  # Every non-sidecar file is cases/<family>/<name>.json, carries the case format, names its
  # own directory as its family, and holds a list of case objects that each name a surface.
  defp load_additive_case_files(files, map, spec) do
    loaded =
      files
      |> Enum.reject(fn {path, _hash, _count} -> additive_sidecar?(path) end)
      |> Enum.map(fn {path, _hash, _count} ->
        {path, load_additive_case_file(path, map, spec)}
      end)

    if Enum.all?(loaded, &match?({_path, {:ok, _cases}}, &1)),
      do: {:ok, Enum.map(loaded, fn {path, {:ok, cases}} -> {path, cases} end)},
      else: {:error, :invalid}
  end

  defp load_additive_case_file(path, map, %{case_format: case_format}) do
    with ["cases", family, name] <- String.split(path, "/"),
         true <- String.ends_with?(name, ".json"),
         {:ok, file} <- decode_plain(map, path),
         true <- file["format"] == case_format,
         true <- file["family"] == family,
         cases when is_list(cases) and cases != [] <- file["cases"],
         true <- Enum.all?(cases, &additive_case?/1) do
      {:ok, Enum.map(cases, &Map.put(&1, "family", family))}
    else
      _invalid -> :error
    end
  end

  defp additive_case?(%{"id" => id, "surface" => surface})
       when is_binary(id) and is_binary(surface),
       do: true

  defp additive_case?(_case_obj), do: false

  defp verify_additive_counts(index, files, cases) do
    per_file = Map.new(cases, fn {path, list} -> {path, length(list)} end)

    files_agree? =
      Enum.all?(files, fn {path, _hash, count} ->
        if additive_sidecar?(path), do: count == 0, else: Map.get(per_file, path) == count
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

  # --- sibling-profile corpora ---------------------------------------------

  # Each sibling corpus has a closed index: exactly these members, an exact ordered file list of
  # {path, sha256} (lowercase hex), revision 1, and per-kind case counts. Each case is tagged with
  # its kind here so the runner dispatches on data the loader verified.
  @local_loopback_http %{
    major: :local_loopback_http,
    profile: "bap-application-proof/local-loopback-http/1",
    index_keys: ["files", "profile", "proof_cases", "revision", "uri_cases"],
    files: ["profile.json", "proof-cases.json"]
  }

  @role_attestation %{
    major: :role_attestation,
    profile: "bap-role-attestation/1",
    index_keys: ["attestation_cases", "files", "profile", "revision"],
    files: ["profile.json", "attestation-cases.json"]
  }

  @content_assertion %{
    major: :content_assertion,
    profile: "bap-content-assertion/1",
    index_keys: [
      "assertion_cases",
      "digest_cases",
      "files",
      "private_material_tracked",
      "profile",
      "revision",
      "successor_cases"
    ],
    files: [
      "profile.json",
      "digest-cases.json",
      "assertion-structure-cases.json",
      "assertion-verification-cases.json",
      "successor-cases.json",
      "content-base.raw",
      "content-maximum.raw",
      "content-over-limit.raw"
    ]
  }

  @doc "Loads and integrity-verifies the local-loopback HTTP application-profile corpus map."
  @spec load_local_loopback_http(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_local_loopback_http(map) when is_map(map) do
    with {:ok, index_bytes, index, profile} <- load_sibling(map, @local_loopback_http),
         uri_cases when is_list(uri_cases) <- profile["uri_cases"],
         proofs when is_map(proofs) and map_size(proofs) > 0 <- profile["proofs"],
         {:ok, proof_cases} <- decode_case_list(map, "proof-cases.json"),
         true <- length(uri_cases) == index["uri_cases"],
         true <- length(proof_cases) == index["proof_cases"] do
      certified =
        proofs
        |> Map.to_list()
        |> Enum.sort_by(&elem(&1, 0))
        |> Enum.map(fn {family, proof} -> certified_proof_case(family, proof) end)

      cases = [
        {"profile.json", tag_cases(uri_cases, "uri") ++ certified},
        {"proof-cases.json", tag_cases(proof_cases, "proof")}
      ]

      sibling_corpus(index_bytes, index, profile, cases, %{}, :local_loopback_http)
    else
      _invalid -> {:error, :invalid}
    end
  end

  def load_local_loopback_http(_map), do: {:error, :invalid}

  @doc "Loads and integrity-verifies the role-attestation profile corpus map."
  @spec load_role_attestation(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_role_attestation(map) when is_map(map) do
    with {:ok, index_bytes, index, profile} <- load_sibling(map, @role_attestation),
         {:ok, cases} <- decode_case_list(map, "attestation-cases.json"),
         true <- length(cases) == index["attestation_cases"] do
      sibling_corpus(
        index_bytes,
        index,
        profile,
        [{"attestation-cases.json", tag_cases(cases, "attestation")}],
        %{},
        :role_attestation
      )
    else
      _invalid -> {:error, :invalid}
    end
  end

  def load_role_attestation(_map), do: {:error, :invalid}

  @doc "Loads and integrity-verifies the content-assertion profile corpus map."
  @spec load_content_assertion(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load_content_assertion(map) when is_map(map) do
    with {:ok, index_bytes, index, profile} <- load_sibling(map, @content_assertion),
         true <- index["private_material_tracked"] == false,
         {:ok, digest} <- decode_case_list(map, "digest-cases.json"),
         {:ok, structure} <- decode_case_list(map, "assertion-structure-cases.json"),
         {:ok, verification} <- decode_case_list(map, "assertion-verification-cases.json"),
         {:ok, successor} <- decode_case_list(map, "successor-cases.json"),
         true <- length(digest) == index["digest_cases"],
         true <- length(structure) + length(verification) == index["assertion_cases"],
         true <- length(successor) == index["successor_cases"],
         raws = content_raws(map),
         true <- content_sidecar_bound?(profile, raws) do
      cases = [
        {"digest-cases.json", tag_cases(digest, "digest")},
        {"assertion-structure-cases.json", tag_cases(structure, "assertion")},
        {"assertion-verification-cases.json", tag_cases(verification, "assertion")},
        {"successor-cases.json", tag_cases(successor, "successor")}
      ]

      sibling_corpus(index_bytes, index, profile, cases, raws, :content_assertion)
    else
      _invalid -> {:error, :invalid}
    end
  end

  def load_content_assertion(_map), do: {:error, :invalid}

  defp load_sibling(map, %{profile: profile_name, index_keys: keys, files: paths}) do
    with {:ok, index_bytes} <- fetch_index(map),
         {:ok, index} <- decode_index(index_bytes),
         true <- exact_keys?(index, keys),
         true <- index["profile"] == profile_name and index["revision"] == 1,
         {:ok, files} <- sibling_files(index["files"]),
         true <- Enum.map(files, &elem(&1, 0)) == paths,
         :ok <- verify_file_set(Enum.map(files, fn {path, hash} -> {path, hash, 0} end), map),
         true <- Enum.all?(files, fn {path, hash} -> additive_hash_matches?(map, path, hash) end),
         {:ok, profile} <- decode_plain(map, "profile.json"),
         true <- profile["profile"] == profile_name and profile["revision"] == 1 do
      {:ok, index_bytes, index, profile}
    else
      _invalid -> {:error, :invalid}
    end
  end

  defp exact_keys?(map, keys) do
    present = Map.keys(map)
    length(present) == length(keys) and present -- keys == []
  end

  defp sibling_files(entries) when is_list(entries) do
    files = Enum.map(entries, &sibling_file/1)
    if Enum.all?(files, &is_tuple/1), do: {:ok, files}, else: {:error, :invalid}
  end

  defp sibling_files(_entries), do: {:error, :invalid}

  defp sibling_file(%{"path" => path, "sha256" => hash} = entry)
       when is_binary(path) and is_binary(hash) and map_size(entry) == 2,
       do: {path, hash}

  defp sibling_file(_entry), do: :invalid

  defp decode_case_list(map, path) do
    with {:ok, bytes} <- fetch_path(map, path),
         {:ok, {:array, items}} <- Json.decode(bytes, Bounds.maximum()),
         cases = Enum.map(items, &to_plain/1),
         true <- Enum.all?(cases, &sibling_case?/1) do
      {:ok, cases}
    else
      _invalid -> {:error, :invalid}
    end
  end

  defp sibling_case?(%{"id" => id}) when is_binary(id), do: true
  defp sibling_case?(_case_obj), do: false

  defp tag_cases(cases, kind), do: Enum.map(cases, &Map.put(&1, "kind", kind))

  defp certified_proof_case(family, proof) when is_map(proof),
    do: proof |> Map.put("id", "proofs/" <> family) |> Map.put("kind", "certified_proof")

  defp certified_proof_case(family, _proof),
    do: %{"id" => "proofs/" <> family, "kind" => "certified_proof"}

  # load_sibling already proved every indexed file present with its digest.
  defp content_raws(map) do
    Map.new(["content-base.raw", "content-maximum.raw", "content-over-limit.raw"], fn path ->
      bytes = Map.fetch!(map, path)
      {path, {bytes, sha256_hex(bytes)}}
    end)
  end

  # profile.json names the base content file and its digest; it must be one of the indexed raws.
  defp content_sidecar_bound?(%{"content" => %{"path" => path, "sha256" => hash}}, raws) do
    case Map.get(raws, path) do
      {_bytes, ^hash} -> true
      _other -> false
    end
  end

  defp content_sidecar_bound?(_profile, _raws), do: false

  defp sibling_corpus(index_bytes, index, profile, cases, raws, major) do
    with :ok <- verify_case_ids(cases) do
      total = Enum.reduce(cases, 0, fn {_path, list}, acc -> acc + length(list) end)

      {:ok,
       %__MODULE__{
         index: index,
         index_bytes: index_bytes,
         cases: cases,
         raws: raws,
         case_ids: cases |> Enum.flat_map(&elem(&1, 1)) |> Enum.map(& &1["id"]) |> MapSet.new(),
         major: major,
         profile: profile,
         total_cases: total
       }}
    end
  end

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
