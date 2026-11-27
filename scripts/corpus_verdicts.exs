Code.require_file("corpus_catalog.exs", __DIR__)

defmodule BoundedAuthorityProtocol.CorpusVerdicts do
  @moduledoc false
  alias BoundedAuthorityProtocol.CorpusCatalog, as: Catalog
  alias BoundedAuthorityProtocol.V1.{Bounds, Jcs}

  # The projection contract and normative citations live in
  # docs/design/corpus-verdict-digests.md. Index order is intentional: Corpus.load/1 sorts
  # paths and accumulates case files in reverse, so its storage order is NOT digest order.
  # Envelope/profile metadata and certified proof fixtures without case IDs are not cases.
  def cases(root, index) do
    Enum.flat_map(index["files"], fn entry ->
      path = entry["path"]

      if String.ends_with?(path, ".json") and path != "revision.json" do
        doc = root |> Path.join(path) |> File.read!() |> :json.decode()

        list =
          if is_list(doc), do: doc, else: Map.get(doc, "cases", Map.get(doc, "uri_cases", []))

        Enum.map(list, &{path, &1})
      else
        []
      end
    end)
  end

  # Projection table: docs/design/corpus-verdict-digests.md. The surface schemas are
  # normatively attached to bap-local-loopback-http-v1 §6 (URI rules §3),
  # bap-role-attestation-v1 §6, and bap-v1 §14.1's indexed strict profile case_envelope.
  def outcome(%{"expected" => expected}, _corpus, _file), do: expected

  def outcome(case_obj, "application-profiles/local-loopback-http/v1", "profile.json") do
    case case_obj do
      %{"valid" => true, "normalized" => text} when is_binary(text) ->
        %{"valid" => true, "normalized" => text}

      %{"valid" => false} ->
        if Map.has_key?(case_obj, "normalized"), do: raise("invalid URI declares normalized")
        %{"valid" => false}

      _ ->
        raise "URI case lacks its declared outcome members"
    end
  end

  def outcome(case_obj, corpus, file) do
    keys =
      case {corpus, file, case_obj["surface"]} do
        {"application-profiles/local-loopback-http/v1", "proof-cases.json", _} ->
          ["decode_local", "decode_standard", "envelope_local"]

        {"attestation-profiles/role-attestation/v1", "attestation-cases.json", _} ->
          ["decode", "verify"]

        {"strict-ed25519", _, "local_loopback_http"} ->
          ["decode_local", "decode_standard", "envelope_local"]

        {corpus, _, "role_attestation"} when corpus in ["strict-ed25519", "string-or-uri"] ->
          ["decode", "verify"]

        _ ->
          raise "case has neither expected nor a declared outcome schema"
      end

    Map.new(keys, fn key ->
      value = Map.fetch!(case_obj, key)
      unless is_boolean(value), do: raise("declared outcome #{key} is not boolean")
      {key, value}
    end)
  end

  def digest(pairs) do
    # JCS is compositional. Encode each pair through the protocol's JCS encoder, then frame
    # the array without imposing a wire-input array bound on this tooling-only sequence.
    bytes = ["[", Enum.intersperse(Enum.map(pairs, &canonical/1), ","), "]"]
    sha(IO.iodata_to_binary(bytes))
  end

  def canonical(value) when is_list(value) do
    IO.iodata_to_binary(["[", Enum.intersperse(Enum.map(value, &canonical/1), ","), "]"])
  end

  def canonical(value) when is_map(value) do
    members =
      value
      |> Enum.sort_by(fn {key, _} ->
        :unicode.characters_to_binary(key, :utf8, {:utf16, :big})
      end)
      |> Enum.map(fn {key, member} -> [canonical(key), ":", canonical(member)] end)

    IO.iodata_to_binary(["{", Enum.intersperse(members, ","), "}"])
  end

  def canonical(value) do
    {:ok, bytes} = Jcs.encode(tagged(value), Bounds.maximum())
    bytes
  end

  def manifest do
    corpora =
      Map.new(Catalog.entries(), fn entry ->
        root = Path.join(Catalog.root(), entry.source)
        index_bytes = File.read!(Path.join(root, "index.json"))
        index = :json.decode(index_bytes)

        files =
          Map.new(
            Path.wildcard(Path.join(root, "**/*")) |> Enum.filter(&File.regular?/1),
            fn path -> {Path.relative_to(path, root), File.read!(path)} end
          )

        {:ok, _loaded} = BoundedAuthorityProtocol.Conformance.Corpus.load_any(files)
        cases = cases(root, index)
        ids = Enum.map(cases, fn {_, case_obj} -> Map.fetch!(case_obj, "id") end)
        if length(ids) != MapSet.size(MapSet.new(ids)), do: raise("duplicate case IDs")
        corpus = Path.relative_to(entry.source, "priv/conformance")

        pairs =
          Enum.map(cases, fn {path, case_obj} ->
            [case_obj["id"], outcome(case_obj, corpus, path)]
          end)

        {Path.relative_to(entry.source, "priv/conformance"),
         %{
           "index_sha256_base64url" => sha(index_bytes),
           "case_count" => length(cases),
           "verdict_digest_sha256_base64url" => digest(pairs)
         }}
      end)

    canonical(%{"format" => "bap-corpus-verdict-digests/1", "corpora" => corpora})
  end

  def sha(bytes), do: :crypto.hash(:sha256, bytes) |> Base.url_encode64(padding: false)
  defp tagged(nil), do: :null
  defp tagged(:null), do: :null
  defp tagged(v) when is_boolean(v), do: {:boolean, v}
  defp tagged(v) when is_integer(v), do: {:integer, v}
  defp tagged(v) when is_float(v), do: {:float, v}
  defp tagged(v) when is_binary(v), do: {:string, v}
end
