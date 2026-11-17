defmodule BoundedAuthorityProtocol.CiConfigurationTest do
  use ExUnit.Case, async: true

  # A public repository: every job runs on a GitHub-hosted runner, never a self-hosted one.
  @runner "ubuntu-24.04"
  @gate ".github/workflows/ci.yml"
  # Maintainers dispatch publication and site deployment only after landing.
  @not_gates [".github/workflows/pages.yml", ".github/workflows/publish.yml"]

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

  test "every executable job has a timeout and every checkout discards credentials" do
    for path <- workflows(), {name, job} <- read(path)["jobs"] do
      if Map.has_key?(job, "steps") do
        timeout = job["timeout-minutes"]

        if is_integer(timeout) do
          assert timeout >= 5, "#{path} job #{name} must have a timeout with a 5-minute floor"
        else
          assert timeout == "${{ matrix.timeout }}", "#{path} job #{name} has no timeout"

          for entry <- job["strategy"]["matrix"]["include"] do
            assert is_integer(entry["timeout"]) and entry["timeout"] >= 5
          end
        end
      else
        refute Map.has_key?(job, "timeout-minutes"), "reusable callers cannot take a timeout"
      end

      for step <- job["steps"] || [], uses?(step, "actions/checkout@") do
        assert step["with"]["persist-credentials"] == false, "#{path} job #{name}"
      end
    end
  end

  # A landing qualifies on one run of ci.yml, so every check is part of that run: a gate that
  # starts itself on a push or pull request would run beside the landing without gating it.
  test "every check is part of the one CI run that gates a landing" do
    ci = read(@gate)
    assert ci["name"] == "CI"
    assert ci["on"] == %{"push" => %{"branches" => ["kci/**"]}}

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

  test "qualified needs every other job and refuses every non-success result" do
    jobs = read(@gate)["jobs"]
    qualified = jobs["qualified"]
    assert qualified["if"] == "always()"
    assert MapSet.new(qualified["needs"]) == MapSet.new(Map.keys(jobs) -- ["qualified"])
    [step] = qualified["steps"]
    assert step["env"]["NEEDS_JSON"] == "${{ toJSON(needs) }}"
    refute step["run"] =~ "${{"

    success = Map.new(qualified["needs"], &{&1, %{"result" => "success"}})

    check = fn needs ->
      System.cmd("bash", ["-c", step["run"]],
        env: [{"NEEDS_JSON", needs |> :json.encode() |> IO.iodata_to_binary()}],
        stderr_to_stdout: true
      )
    end

    assert {_, 0} = check.(success)

    for name <- qualified["needs"], result <- ["failure", "skipped", "cancelled"] do
      {_, status} = check.(Map.put(success, name, %{"result" => result}))
      assert status != 0, "qualified accepted #{name}=#{result}"
    end

    {_, status} = check.(%{})
    assert status != 0
  end

  test "history gates require complete checkout and qualification includes attestation" do
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

    refute Map.has_key?(attest, "if")

    assert attest["permissions"]["id-token"] == "write"
    assert read(".github/workflows/supply-chain.yml")["permissions"] == %{"contents" => "read"}
  end

  test "dependency review always compares the default branch with the candidate commit" do
    refute Map.has_key?(read(@gate)["jobs"]["dependency-review"], "if")
    [job] = Map.values(read(".github/workflows/dependency-review.yml")["jobs"])
    step = Enum.find(job["steps"], &uses?(&1, "actions/dependency-review-action@"))
    assert step["with"]["base-ref"] == "${{ github.event.repository.default_branch }}"
    assert step["with"]["head-ref"] == "${{ github.sha }}"
  end

  test "BEAM installations are strict and primary toolchains read the version file" do
    for path <- workflows(), {_name, job} <- read(path)["jobs"], step <- job["steps"] || [] do
      if uses?(step, "erlef/setup-beam@") do
        assert step["with"]["version-type"] == "strict"

        assert step["with"]["version-file"] == ".tool-versions" or
                 (step["with"]["elixir-version"] == "${{ matrix.elixir }}" and
                    step["with"]["otp-version"] == "${{ matrix.otp }}")
      end
    end

    ci = read(@gate)
    legs = ci["jobs"]["compatibility"]["strategy"]["matrix"]["include"]

    assert Enum.map(Enum.reject(legs, & &1["primary"]), &{&1["elixir"], &1["otp"]}) == [
             {"1.18.4", "27.3.4.14"},
             {"1.19.5", "28.5.0.3"}
           ]

    quality_steps = ci["jobs"]["quality"]["steps"]
    node = Enum.find(quality_steps, &uses?(&1, "actions/setup-node@"))
    go = Enum.find(quality_steps, &uses?(&1, "actions/setup-go@"))
    assert node["with"]["node-version-file"] == ".tool-versions"
    assert go["with"]["go-version-file"] == ".tool-versions"

    for step <- quality_steps, String.contains?(step["run"] || "", "mix deps.get") do
      assert step["run"] == "mix deps.get --check-locked"
    end
  end

  test "Pages deploys only when a maintainer dispatches it from the default branch" do
    pages = read(".github/workflows/pages.yml")
    assert pages["on"] == %{"workflow_dispatch" => nil}
    publish = read(".github/workflows/publish.yml")
    assert pages["jobs"]["build"]["if"] == publish["jobs"]["publish"]["if"]
    assert pages["jobs"]["deploy"]["needs"] == "build"
    assert_default_branch_first(pages["jobs"]["build"])
    assert pages["jobs"]["deploy"]["environment"]["name"] == "github-pages"
  end

  test "Hex publication is dispatch-only, maintainer-restricted and environment-scoped" do
    path = ".github/workflows/publish.yml"
    workflow = read(path)
    assert workflow["on"] == %{"workflow_dispatch" => nil}
    assert workflow["permissions"] == %{"contents" => "read"}
    [job] = Map.values(workflow["jobs"])
    assert job["environment"] == "publish"

    assert job["if"] ==
             ~s|contains(fromJSON('["corepay","palermo-git"]'), github.actor) && contains(fromJSON('["corepay","palermo-git"]'), github.triggering_actor)|

    assert_default_branch_first(job)
    refute Map.has_key?(workflow, "env")
    refute Map.has_key?(job, "env")
    steps = job["steps"]
    [publish] = Enum.filter(steps, &String.contains?(&1["run"] || "", "mix hex.publish"))
    assert publish["run"] == "mix hex.publish --yes"
    assert publish["env"] == %{"HEX_API_KEY" => "${{ secrets.HEX_API_KEY }}"}
    assert List.last(steps) == publish

    # Remove the one allowed declaration; no other workflow location may carry this key.
    without_key = put_in(workflow, ["jobs", "publish", "steps"], steps -- [publish])
    refute inspect(without_key) =~ "HEX_API_KEY"

    for other <- workflows() -- [path] do
      refute File.read!(other) =~ "HEX_API_KEY", other
    end

    for step <- steps do
      refute uses?(step, "actions/cache")
      refute Map.has_key?(step["with"] || %{}, "cache")
    end

    version_guard = Enum.find(steps, &String.contains?(&1["run"] || "", "git ls-remote"))
    assert version_guard["run"] =~ "@version"
    assert version_guard["run"] =~
             "https://hex.pm/api/packages/bounded_authority_protocol/releases/"
    assert version_guard["run"] =~ "200)"
    assert version_guard["run"] =~ "404)"
    assert version_guard["run"] =~ "refs/tags/v$version"

    commands = Enum.map(steps, &(&1["run"] || ""))
    assert "mix deps.get --check-locked" in commands
    docs = Enum.find_index(commands, &(&1 == "mix docs"))
    build = Enum.find_index(commands, &(&1 == "mix hex.build"))
    inspect_package = Enum.find_index(commands, &String.contains?(&1, "inspect_publish_package"))
    assert is_integer(docs) and is_integer(build) and is_integer(inspect_package)
    assert docs < build and build < inspect_package and inspect_package < length(steps) - 1
  end

  test "the attested package passed the complete quality gate in the job that built it" do
    ci = read(@gate)
    assert ci["jobs"]["attest"]["needs"] == "quality"
    assert ci["jobs"]["attest"]["with"]["version"] == "${{ needs.quality.outputs.version }}"

    steps = ci["jobs"]["quality"]["steps"]
    quality = Enum.find_index(steps, &(&1["run"] == "mix quality"))
    archive = Enum.find_index(steps, &String.contains?(&1["run"] || "", "mix hex.build"))

    inspect_package =
      Enum.find_index(steps, &String.contains?(&1["run"] || "", "inspect_publish_package"))

    assert quality != nil and archive != nil and quality < archive
    assert is_integer(inspect_package) and archive < inspect_package
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

  defp assert_default_branch_first(job) do
    [first | _] = job["steps"]
    refute Map.has_key?(first, "if")
    refute Map.has_key?(first, "uses")
    assert first["env"]["DEFAULT_BRANCH"] == "${{ github.event.repository.default_branch }}"
    assert first["run"] =~ ~s(if [ "$GITHUB_REF" != "refs/heads/$DEFAULT_BRANCH" ])
    assert first["run"] =~ "exit 1"

    for ref <- ["refs/heads/main", "refs/heads/kci/candidate", "refs/tags/v1.0.0"] do
      {_, status} =
        System.cmd("bash", ["-c", first["run"]],
          env: [{"DEFAULT_BRANCH", "main"}, {"GITHUB_REF", ref}],
          stderr_to_stdout: true
        )

      assert (status == 0) == (ref == "refs/heads/main")
    end
  end
end
