defmodule BoundedAuthorityProtocol.Architecture.SbomGenerationTest do
  use ExUnit.Case, async: false

  @root Path.expand("../..", __DIR__)
  @generator "cmd mix run --no-start scripts/generate_sbom.exs "
  @options "--exclude-system-dependencies --classification library --schema 1.6 --format json --output "

  test "supply-chain CI reaches only the SBOM generator that skips Hex application startup" do
    workflow =
      @root
      |> Path.join(".github/workflows/supply-chain.yml")
      |> File.read!()
      |> YamlElixir.read_from_string!()

    steps = workflow["jobs"]["package"]["steps"]
    quality = Enum.find(steps, &(&1["name"] == "Run complete quality gate"))
    assert quality["run"] == "mix quality"
    refute Enum.any?(steps, &String.contains?(&1["run"] || "", "sbom.cyclonedx"))

    aliases = Mix.Project.config()[:aliases]
    assert "audit" in aliases[:quality]
    assert "sbom.generate" in aliases[:audit]

    assert Enum.filter(aliases[:"sbom.generate"], &is_binary/1) == [
             @generator <> "--only prod " <> @options <> "artifacts/release.cdx.json --force",
             "cmd elixir scripts/prune_release_sbom.exs artifacts/release.cdx.json",
             @generator <> @options <> "artifacts/tooling.cdx.json --force"
           ]
  end

  test "both real SBOMs are generated without starting hex_core or ssh" do
    {output, status} =
      System.cmd("mix", ["sbom.generate"],
        cd: @root,
        env: [{"MIX_ENV", "test"}],
        stderr_to_stdout: true
      )

    assert status == 0, output
    assert length(Regex.scan(~r/SBOM generated; hex_core=stopped, ssh=stopped/, output)) == 2

    release = @root |> Path.join("artifacts/release.cdx.json") |> File.read!() |> :json.decode()
    tooling = @root |> Path.join("artifacts/tooling.cdx.json") |> File.read!() |> :json.decode()

    assert release["bomFormat"] == "CycloneDX"
    assert release["components"] in [nil, []]
    assert Enum.any?(tooling["components"], &(&1["name"] == "sbom" and &1["version"] == "0.11.0"))

    assert Enum.any?(
             tooling["components"],
             &(&1["name"] == "protobuf" and &1["version"] == "0.17.1")
           )

    {license_output, license_status} =
      System.cmd(
        "elixir",
        ["scripts/check_dependency_licenses.exs", "artifacts/tooling.cdx.json"],
        cd: @root,
        stderr_to_stdout: true
      )

    assert license_status == 0, license_output
    assert license_output =~ "dependency license boundary passed"
  end
end
