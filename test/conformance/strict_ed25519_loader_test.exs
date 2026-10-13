defmodule BoundedAuthorityProtocol.Conformance.StrictEd25519LoaderTest do
  @moduledoc """
  Malformed-input paths of the strict-Ed25519 corpus loader and runner.

  Each test starts from the shipped corpus (which loads, the positive control) and changes one
  thing, so the refusal is attributable to that one defect: a non-map input, an index file entry
  of the wrong shape, a declared file whose value is not bytes, a case without a surface, a
  primitive case with no input, an unknown primitive function, and an unknown surface.
  """

  use ExUnit.Case, async: true

  alias BoundedAuthorityProtocol.Conformance.Corpus
  alias BoundedAuthorityProtocol.Conformance.Runner

  @root Path.expand("../../priv/conformance/strict-ed25519", __DIR__)

  setup_all do
    map =
      Path.join(@root, "**/*")
      |> Path.wildcard()
      |> Enum.reject(&File.dir?/1)
      |> Map.new(fn path -> {Path.relative_to(path, @root), File.read!(path)} end)

    %{map: map}
  end

  test "the shipped corpus map loads (positive control)", %{map: map} do
    assert {:ok, %Corpus{major: :strict_ed25519}} = Corpus.load_strict_ed25519(map)
  end

  test "an input that is not a map is refused" do
    for input <- [nil, "index.json", [{"index.json", "{}"}]] do
      assert {:error, :invalid} = Corpus.load_strict_ed25519(input)
    end
  end

  test "an index file entry without the path, sha256 and cases members is refused", %{map: map} do
    index = :json.decode(map["index.json"])
    [first | rest] = index["files"]
    broken = Map.put(index, "files", [Map.delete(first, "cases") | rest])

    assert {:error, :invalid} =
             Corpus.load_strict_ed25519(Map.put(map, "index.json", JSON.encode!(broken)))
  end

  test "a declared file whose map value is not bytes is refused", %{map: map} do
    path = "cases/taming/speccheck.json"
    assert is_binary(map[path])

    assert {:error, :invalid} = Corpus.load_strict_ed25519(Map.put(map, path, 12_345))
  end

  test "a case without a surface is refused", %{map: map} do
    path = "cases/taming/speccheck.json"
    file = :json.decode(map[path])
    [first | rest] = file["cases"]
    bytes = JSON.encode!(Map.put(file, "cases", [Map.delete(first, "surface") | rest]))

    # Re-pin the edited file in the index so only the missing surface can refuse it.
    index = :json.decode(map["index.json"])

    files =
      Enum.map(index["files"], fn
        %{"path" => ^path} = entry -> Map.put(entry, "sha256", sha256_hex(bytes))
        entry -> entry
      end)

    edited =
      map
      |> Map.put(path, bytes)
      |> Map.put("index.json", JSON.encode!(Map.put(index, "files", files)))

    assert {:error, :invalid} = Corpus.load_strict_ed25519(edited)
  end

  describe "the strict runner" do
    test "a primitive case with no input, an unknown primitive and an unknown surface disagree" do
      honest = %{
        "id" => "control",
        "surface" => "ed25519.acceptable_public_key",
        "input" => %{"public_key" => "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
        "expected" => %{"verdict" => "valid"}
      }

      malformed = [
        %{
          "id" => "no-input",
          "surface" => "ed25519.verify_strict",
          "expected" => %{"verdict" => "invalid"}
        },
        %{
          "id" => "unknown-primitive",
          "surface" => "ed25519.verify_cofactored",
          "input" => honest["input"],
          "expected" => %{"verdict" => "invalid"}
        },
        %{"id" => "unknown-surface", "surface" => "no_such_surface"}
      ]

      corpus = %Corpus{
        index: %{},
        index_bytes: "",
        cases: [{"cases/primitive/synthetic.json", [honest | malformed]}],
        raws: %{},
        case_ids: MapSet.new(),
        major: :strict_ed25519
      }

      [{_path, results}] = Runner.run(corpus)

      assert Map.new(results, &{&1.case_id, &1.agree}) == %{
               "control" => true,
               "no-input" => false,
               "unknown-primitive" => false,
               "unknown-surface" => false
             }
    end
  end

  defp sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
