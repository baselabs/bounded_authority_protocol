defmodule BoundedAuthorityProtocol.Ed25519OwnerTest do
  @moduledoc """
  `BoundedAuthorityProtocol.Ed25519` is the single owner of Ed25519 verification.

  No module under `lib/` other than the owner may call the `:crypto` EdDSA verify directly:
  every surface goes through `verify_strict/3`, so rule S1 cannot be bypassed by a new or
  refactored call site. The unchecked thumbprint digest is reserved for the corpus census and
  is never reachable from a verification path.

  The source scan below is backed by a check of the compiled code: every module of the
  application is read from its BEAM file, and its imports chunk (every static remote call the
  compiler emitted, as module, function and arity) must show `:crypto.verify/5` only in the
  Ed25519 owner and the ES256 suite module, and `:public_key.verify` nowhere. That check does not
  depend on source layout, aliases or macros.
  """

  use ExUnit.Case, async: true

  @owner "lib/bounded_authority_protocol/ed25519.ex"

  # Matches the direct call in any layout: inline, wrapped after the paren, or with the
  # module and function split by whitespace.
  @raw_verify ~r/:crypto\s*\.\s*verify\s*\(\s*:eddsa\b/

  # The only files that may name the unchecked thumbprint digest: its definition, the
  # corpus census, its own unit test, and this test.
  @unchecked_allowlist [
    "lib/bounded_authority_protocol/v1/jwk.ex",
    "test/architecture/ed25519_owner_test.exs",
    "test/bounded_authority_protocol/v1/jwk_test.exs",
    "test/conformance/corpus_test.exs"
  ]

  # The only modules whose compiled code may call :crypto.verify/5.
  @crypto_verify_callers MapSet.new([
                           BoundedAuthorityProtocol.Ed25519,
                           BoundedAuthorityProtocol.Es256
                         ])

  test "compiled code: only the Ed25519 owner and the ES256 suite call :crypto.verify/5" do
    imports = compiled_imports()

    # Known positives: the scan reads every application module, and both expected callers
    # carry the import, so an empty set below is a fact about the code, not a blind instrument.
    assert map_size(imports) > 100
    assert Map.has_key?(imports, BoundedAuthorityProtocol.V1.Jwk)

    callers =
      for {module, mfas} <- imports,
          Enum.any?(mfas, &match?({:crypto, :verify, _}, &1)),
          into: MapSet.new(),
          do: module

    assert callers == @crypto_verify_callers,
           "modules calling :crypto.verify outside the owners: " <>
             inspect(MapSet.to_list(MapSet.difference(callers, @crypto_verify_callers)))

    for module <- @crypto_verify_callers do
      assert {:crypto, :verify, 5} in imports[module], inspect(module)
    end
  end

  test "compiled code: no module calls :public_key.verify" do
    callers =
      for {module, mfas} <- compiled_imports(),
          Enum.any?(mfas, &match?({:public_key, :verify, _}, &1)),
          do: module

    assert callers == []
  end

  test "no lib module outside the owner calls the raw :crypto EdDSA verify" do
    files = source_files("lib")

    # Known positives: the scan reaches the owner and the owner's own call matches, so an
    # empty finding list below is a fact about lib/, not a blind instrument.
    assert @owner in files
    assert length(files) > 100
    assert raw_verify_sites(@owner) != []

    findings =
      for path <- files, path != @owner, line <- raw_verify_sites(path), do: "#{path}:#{line}"

    assert findings == [],
           "raw :crypto.verify(:eddsa ...) outside #{@owner}; call " <>
             "BoundedAuthorityProtocol.Ed25519.verify_strict/3 instead:\n" <>
             Enum.join(findings, "\n")
  end

  test "the raw-verify pattern sees every call layout" do
    for source <- [
          ":crypto.verify(:eddsa, :none, m, s, [k, :ed25519])",
          ":crypto.verify(\n  :eddsa,\n  :none,\n  m,\n  s,\n  [k, :ed25519]\n)",
          ":crypto.verify( :eddsa, :none, m, s, [k, :ed25519])",
          ":crypto .verify(:eddsa, :none, m, s, [k, :ed25519])"
        ] do
      assert Regex.match?(@raw_verify, source), source
    end

    for source <- [
          ":crypto.verify(:ecdsa, :sha256, m, s, [k, :secp256r1])",
          "Ed25519.verify_strict(m, s, k)",
          ":crypto.sign(:eddsa, :none, m, [k, :ed25519])"
        ] do
      refute Regex.match?(@raw_verify, source), source
    end
  end

  test "the unchecked thumbprint digest is named only by its definition and the census" do
    files = source_files("lib") ++ source_files("test") ++ source_files("scripts")

    callers =
      files
      |> Enum.filter(&(File.read!(&1) =~ "thumbprint_digest_unchecked"))
      |> Enum.sort()

    # Known positive: the definition is found.
    assert "lib/bounded_authority_protocol/v1/jwk.ex" in callers
    assert callers -- @unchecked_allowlist == []
  end

  # Module => the {module, function, arity} imports its BEAM file records. The files are read
  # from the application's ebin directory, not through :code.which/1, because under
  # `mix test --cover` the loaded modules are cover-compiled and have no file of their own.
  defp compiled_imports do
    {:ok, modules} = :application.get_key(:bounded_authority_protocol, :modules)
    ebin = :code.lib_dir(:bounded_authority_protocol) |> Path.join("ebin")

    Map.new(modules, fn module ->
      path = ebin |> Path.join("#{module}.beam") |> String.to_charlist()
      {:ok, {^module, [imports: imports]}} = :beam_lib.chunks(path, [:imports])
      {module, imports}
    end)
  end

  defp source_files(root) do
    root
    |> Path.join("**/*.{ex,exs}")
    |> Path.wildcard()
    |> Enum.sort()
  end

  defp raw_verify_sites(path) do
    source = File.read!(path)

    @raw_verify
    |> Regex.scan(source, return: :index)
    |> Enum.map(fn [{offset, _length}] ->
      source |> binary_part(0, offset) |> String.split("\n") |> length()
    end)
  end
end
