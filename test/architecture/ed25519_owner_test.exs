defmodule BoundedAuthorityProtocol.Ed25519OwnerTest do
  @moduledoc """
  `BoundedAuthorityProtocol.Ed25519` is the single owner of Ed25519 verification.

  No module under `lib/` other than the owner may call the `:crypto` EdDSA verify directly:
  every surface goes through `verify_strict/3`, so rule S1 cannot be bypassed by a new or
  refactored call site. The unchecked thumbprint digest is reserved for the corpus census and
  is never reachable from a verification path.
  """

  use ExUnit.Case, async: true

  @owner "lib/bounded_authority_protocol/ed25519.ex"

  # Matches the direct call in any layout: inline, wrapped after the paren, or with the
  # module and function split by whitespace.
  @raw_verify ~r/:crypto\s*\.\s*verify\s*\(\s*:eddsa\b/

  # The only files that may name the unchecked thumbprint digest: its definition, the
  # corpus census, and this test.
  @unchecked_allowlist [
    "lib/bounded_authority_protocol/v1/jwk.ex",
    "test/architecture/ed25519_owner_test.exs",
    "test/conformance/corpus_test.exs"
  ]

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
