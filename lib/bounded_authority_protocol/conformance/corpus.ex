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
  """

  alias BoundedAuthorityProtocol.V1.Bounds
  alias BoundedAuthorityProtocol.V1.Json

  @enforce_keys [:index, :index_bytes, :cases, :raws, :case_ids]
  defstruct [:index, :index_bytes, :cases, :raws, :case_ids]

  @type t :: %__MODULE__{
          index: map(),
          index_bytes: binary(),
          cases: [{binary(), [map()]}],
          raws: %{binary() => binary()},
          case_ids: term()
        }

  @doc "Loads and integrity-verifies a `%{path => binary}` corpus map."
  @spec load(%{binary() => binary()}) :: {:ok, t()} | {:error, :invalid}
  def load(map) when is_map(map) do
    with {:ok, index_bytes} <- fetch_index(map),
         {:ok, index} <- decode_index(index_bytes),
         :ok <- verify_structure(index),
         {:ok, files} <- ordered_files(index),
         {:ok, cases, raws} <- load_files(files, map),
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
         case_ids: case_ids
       }}
    end
  end

  def load(_map), do: {:error, :invalid}

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

  defp verify_structure(%{"format" => format} = index)
       when format == "bounded-authority-protocol-v1-conformance-corpus-index" do
    cond do
      not is_list(index["files"]) -> {:error, :invalid}
      not is_list(index["public_key_fingerprints"]) -> {:error, :invalid}
      not is_integer(index["total_cases"]) -> {:error, :invalid}
      not is_map(index["applicability"]) -> {:error, :invalid}
      true -> :ok
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

  defp load_files(files, map) do
    Enum.reduce_while(files, {:ok, [], %{}}, fn {path, hash, _count}, {:ok, cases, raws} ->
      load_one_file(path, hash, map, cases, raws)
    end)
  end

  defp load_one_file(path, hash, map, cases, raws) do
    cond do
      String.ends_with?(path, ".json") ->
        load_json_entry(map, path, cases, raws)

      String.ends_with?(path, ".raw") ->
        load_raw_entry(map, path, hash, cases, raws)

      true ->
        {:halt, {:error, :invalid}}
    end
  end

  defp load_json_entry(map, path, cases, raws) do
    case load_json_file(map, path) do
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

  defp load_json_file(map, path) do
    with {:ok, bytes} <- fetch_path(map, path),
         {:ok, decoded} <- decode_case_file(bytes) do
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

  defp decode_case_file(bytes) do
    case Json.decode(bytes, Bounds.maximum()) do
      {:ok, value} ->
        with {:object, members} <- value,
             {:string, format} <- member(members, "format"),
             true <- format == "bounded-authority-protocol-v1-conformance-cases",
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
        case {observed_file_count(per_file_sums, path), String.ends_with?(path, ".raw"), count} do
          {observed, false, _} when observed != :absent and observed == count ->
            {:cont, {:ok, acc + count}}

          # .raw sidecars carry no cases; their declared count must be 0.
          {:absent, true, 0} ->
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

  defp check_one_tamper(case_obj, by_id) do
    with %{"tamper" => tamper} <- case_obj,
         %{"base_case" => base_id, "byte_index" => index, "xor" => xor}
         when is_integer(index) and is_integer(xor) <- tamper,
         %{} = base <- Map.get(by_id, base_id) do
      if tamper_verbatim_matches?(case_obj, base, index, xor), do: :ok, else: :invalid
    else
      _ -> :ok
    end
  end

  defp tamper_verbatim_matches?(case_obj, base, index, xor) do
    with {:ok, base_bytes} <- tamper_source_bytes(base),
         {:ok, verbatim_bytes} <- tamper_verbatim_bytes(case_obj) do
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

  defp tamper_source_bytes(%{"input" => input}) do
    cond do
      is_binary(input["text"]) ->
        {:ok, input["text"]}

      is_binary(input["base64url"]) ->
        case Base.url_decode64(input["base64url"], padding: false) do
          {:ok, bytes} -> {:ok, bytes}
          :error -> :error
        end

      true ->
        :error
    end
  end

  defp tamper_verbatim_bytes(%{"input" => input}) do
    cond do
      is_binary(input["text"]) ->
        {:ok, input["text"]}

      is_binary(input["base64url"]) ->
        case Base.url_decode64(input["base64url"], padding: false) do
          {:ok, bytes} -> {:ok, bytes}
          :error -> :error
        end

      true ->
        :error
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
