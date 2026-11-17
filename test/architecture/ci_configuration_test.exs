defmodule BoundedAuthorityProtocol.CiConfigurationTest do
  use ExUnit.Case, async: true

  # A public repository: every job runs on a GitHub-hosted runner, never a self-hosted one.
  @runner "ubuntu-24.04"
  @gate ".github/workflows/ci.yml"
  # The Pages deployment publishes site/ after a change is on main; it checks nothing.
  @not_gates [".github/workflows/pages.yml"]

  defp workflows, do: Path.wildcard(".github/workflows/*.{yml,yaml}")
  defp read(path), do: YamlElixir.read_from_file!(path)
  defp uses?(step, action), do: String.starts_with?(step["uses"] || "", action)

  test "every job that runs steps uses a GitHub-hosted runner" do
    for path <- workflows(),
        {name, job} <- read(path)["jobs"],
        not Map.has_key?(job, "uses") do
      assert job["runs-on"] == @runner, "#{path} job #{name} must use #{@runner}"
    end
  end

  # A landing qualifies on one run of ci.yml, so every check is part of that run: a gate that
  # starts itself on a push or pull request would run beside the landing without gating it.
  test "every check is part of the one CI run that gates a landing" do
    ci = read(@gate)
    assert ci["name"] == "CI"
    branches = get_in(ci, ["on", "push", "branches"])
    assert "main" in branches and "kci/**" in branches
    assert Map.has_key?(ci["on"], "pull_request")

    for {_event, filters} <- ci["on"], is_map(filters) do
      refute Map.has_key?(filters, "paths") or Map.has_key?(filters, "paths-ignore"),
             "the gate is never path-filtered"
    end

    called = for {_name, %{"uses" => "./" <> path}} <- ci["jobs"], into: MapSet.new(), do: path
    callees = MapSet.new(workflows() -- [@gate | @not_gates])
    assert MapSet.size(callees) >= 4
    assert called == callees, "ci.yml must call exactly #{inspect(MapSet.to_list(callees))}"

    for path <- callees do
      assert Map.keys(read(path)["on"]) == ["workflow_call"], "#{path} runs only when called"
      refute Map.has_key?(read(path), "concurrency"), "#{path} leaves concurrency to ci.yml"
    end
  end

  test "history gates require complete checkout and landing builds cannot attest" do
    ci = read(@gate)
    assert ci["env"]["BAP_REQUIRE_FULL_HISTORY"] == "1"
    assert ci["permissions"] == %{"contents" => "read"}

    for {_name, job} <- ci["jobs"],
        steps = job["steps"] || [],
        Enum.any?(steps, &String.contains?(&1["run"] || "", ["mix quality", "mix test"])) do
      checkout = Enum.find(steps, &uses?(&1, "actions/checkout@"))

      assert checkout["with"]["fetch-depth"] == 0
    end

    refute Map.has_key?(ci["jobs"]["quality"], "permissions")

    refute Enum.any?(ci["jobs"]["quality"]["steps"], &uses?(&1, "actions/attest@"))

    attest = ci["jobs"]["attest"]
    assert attest["uses"] == "./.github/workflows/supply-chain.yml"

    assert attest["if"] ==
             "github.event_name != 'schedule' && " <>
               "(github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v'))"

    assert attest["permissions"]["id-token"] == "write"
    assert read(".github/workflows/supply-chain.yml")["permissions"] == %{"contents" => "read"}
  end

  test "the attested package passed the complete quality gate in the job that built it" do
    ci = read(@gate)
    assert ci["jobs"]["attest"]["needs"] == "quality"
    assert ci["jobs"]["attest"]["with"]["version"] == "${{ needs.quality.outputs.version }}"

    steps = ci["jobs"]["quality"]["steps"]
    quality = Enum.find_index(steps, &(&1["run"] == "mix quality"))
    archive = Enum.find_index(steps, &String.contains?(&1["run"] || "", "mix hex.build"))

    assert quality != nil and archive != nil and quality < archive
    refute Map.has_key?(Enum.at(steps, quality), "if"), "mix quality must run on every event"

    [attest] = Map.values(read(".github/workflows/supply-chain.yml")["jobs"])

    assert [%{"with" => %{"name" => name}}] =
             Enum.filter(attest["steps"], &uses?(&1, "actions/download-artifact@"))

    assert Enum.find(steps, &uses?(&1, "actions/upload-artifact@"))["with"]["name"] == name
  end

  test "each committed dependency lock has an update policy and every policy has a manifest" do
    entries = YamlElixir.read_from_file!(".github/dependabot.yml")["updates"]

    manifests = %{
      "mix" => "mix.exs",
      "cargo" => "Cargo.toml",
      "uv" => "pyproject.toml",
      "gomod" => "go.mod"
    }

    locks = %{
      "mix.lock" => "mix",
      "Cargo.lock" => "cargo",
      "uv.lock" => "uv",
      "go.sum" => "gomod"
    }

    {tracked, 0} = System.cmd("git", ["ls-files", "-z"])
    paths = String.split(tracked, <<0>>, trim: true)

    # Any lockfile, of any ecosystem, must be one this test maps; a new kind fails here
    # instead of passing without an update policy.
    unmapped =
      for path <- paths,
          name = Path.basename(path),
          name =~ ~r/(^|[._-])lock(file)?([._-]|$)|\.lockb?$|^pylock(\.[^.]+)?\.toml$|^go\.sum$/i,
          not Map.has_key?(locks, name),
          do: path

    assert unmapped == [], "lockfiles with no mapped ecosystem: #{inspect(unmapped)}"

    for path <- paths, ecosystem = locks[Path.basename(path)], ecosystem != nil do
      directory = if Path.dirname(path) == ".", do: "/", else: "/" <> Path.dirname(path)

      assert Enum.any?(
               entries,
               &(&1["package-ecosystem"] == ecosystem and &1["directory"] == directory)
             ),
             path
    end

    for entry <- entries do
      ecosystem = entry["package-ecosystem"]
      directory = String.trim_leading(entry["directory"], "/")

      if ecosystem == "github-actions" do
        assert directory == "" and Path.wildcard(".github/workflows/*.yml") != []
      else
        assert Map.has_key?(manifests, ecosystem), "unexpected ecosystem #{ecosystem}"
        manifest = Path.join(directory, Map.fetch!(manifests, ecosystem))
        assert manifest in paths, "Dependabot entry has no committed manifest: #{manifest}"
      end
    end
  end
end
