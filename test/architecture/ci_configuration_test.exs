defmodule BoundedAuthorityProtocol.CiConfigurationTest do
  use ExUnit.Case, async: true

  @runner "${{ vars.BASELABS_RUNNER || 'ubuntu-24.04' }}"

  test "every job uses the operator runner expression" do
    for path <- Path.wildcard(".github/workflows/*.{yml,yaml}"),
        {name, job} <- YamlElixir.read_from_file!(path)["jobs"] do
      assert job["runs-on"] == @runner, "#{path} job #{name} must use #{@runner}"
    end
  end

  # Every workflow is a gate on both landing paths (a kci branch, then main) except the Pages
  # deployment, which publishes site/ after a change is on main and checks nothing.
  @not_gates [".github/workflows/pages.yml"]

  test "every gate workflow runs on main and kci pushes" do
    gates = Path.wildcard(".github/workflows/*.{yml,yaml}") -- @not_gates
    assert length(gates) >= 5

    for path <- gates do
      branches = get_in(YamlElixir.read_from_file!(path), ["on", "push", "branches"]) || []
      assert "main" in branches and "kci/**" in branches, "#{path} must run on main and kci/**"
    end
  end

  test "history gates require complete checkout and landing builds cannot attest" do
    for name <- ["ci", "supply-chain"] do
      workflow = YamlElixir.read_from_file!(".github/workflows/#{name}.yml")
      assert workflow["env"]["BAP_REQUIRE_FULL_HISTORY"] == "1"

      for {_name, job} <- workflow["jobs"],
          Enum.any?(job["steps"], &String.contains?(&1["run"] || "", ["mix quality", "mix test"])) do
        checkout =
          Enum.find(job["steps"], &String.starts_with?(&1["uses"] || "", "actions/checkout@"))

        assert checkout["with"]["fetch-depth"] == 0
      end
    end

    supply = YamlElixir.read_from_file!(".github/workflows/supply-chain.yml")
    assert supply["permissions"] == %{"contents" => "read"}
    refute Map.has_key?(supply["jobs"]["package"], "permissions")

    refute Enum.any?(
             supply["jobs"]["package"]["steps"],
             &String.starts_with?(&1["uses"] || "", "actions/attest@")
           )

    assert supply["jobs"]["attest"]["if"] ==
             "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"

    assert supply["jobs"]["attest"]["permissions"]["id-token"] == "write"
  end

  test "the attested package passed the complete quality gate in the job that built it" do
    supply = YamlElixir.read_from_file!(".github/workflows/supply-chain.yml")
    assert supply["jobs"]["attest"]["needs"] == "package"

    steps = supply["jobs"]["package"]["steps"]
    quality = Enum.find_index(steps, &(&1["run"] == "mix quality"))
    archive = Enum.find_index(steps, &String.contains?(&1["run"] || "", "mix hex.build"))

    assert quality != nil and archive != nil and quality < archive
    refute Map.has_key?(Enum.at(steps, quality), "if"), "mix quality must run on every event"
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
