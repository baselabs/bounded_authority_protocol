defmodule BoundedAuthorityProtocol.CiConfigurationTest do
  use ExUnit.Case, async: true

  # A public repository: every job runs on a GitHub-hosted runner, never a self-hosted one.
  @runner "ubuntu-24.04"
  @gate ".github/workflows/ci.yml"
  @quality_jobs ~w(quality-source quality-corpus quality-tests quality-conformance quality-mutations package)
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

  test "every executable job has a 5 to 90 minute timeout and every checkout discards credentials" do
    for path <- workflows(), {name, job} <- read(path)["jobs"] do
      if Map.has_key?(job, "steps") do
        timeout = job["timeout-minutes"]

        if is_integer(timeout) do
          assert timeout >= 5, "#{path} job #{name} must have a timeout with a 5-minute floor"
          assert timeout <= 90, "#{path} job #{name} must not exceed 90 minutes"
        else
          assert timeout == "${{ matrix.timeout }}", "#{path} job #{name} has no timeout"

          entries =
            if name == "compatibility",
              do: compatibility_matrix()["include"],
              else: job["strategy"]["matrix"]["include"]

          for entry <- entries do
            assert is_integer(entry["timeout"]) and entry["timeout"] >= 5 and
                     entry["timeout"] <= 90,
                   "#{path} job #{name} matrix timeouts must be 5 to 90 minutes"
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
    refute Map.has_key?(qualified, "name")
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

    for name <- @quality_jobs do
      refute Map.has_key?(ci["jobs"][name], "permissions")
      refute Enum.any?(ci["jobs"][name]["steps"], &uses?(&1, "actions/attest@"))
    end

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

  test "runtime installations use the shared reader and refuse every installed tool's drift" do
    actions = Path.wildcard(".github/actions/**/action.{yml,yaml}")

    jobs = for path <- workflows(), {name, job} <- read(path)["jobs"], do: {path, name, job}

    composites =
      for path <- actions, read(path)["runs"]["using"] == "composite" do
        {path, "composite", %{"steps" => read(path)["runs"]["steps"]}}
      end

    for {path, name, job} <- jobs ++ composites, steps = job["steps"] || [] do
      for {step, index} <- Enum.with_index(steps) do
        inputs = step["with"] || %{}

        for {key, value} <- inputs do
          refute key =~ "version-file", "#{path} #{name}: setup actions cannot read version files"
          refute value == ".tool-versions", "#{path} #{name}: use reader outputs"
        end

        tool_inputs =
          cond do
            uses?(step, "erlef/setup-beam@") ->
              assert inputs["version-type"] == "strict"
              [{"elixir-version", "elixir", "elixir"}, {"otp-version", "erlang", "otp"}]

            uses?(step, "actions/setup-node@") ->
              [{"node-version", "nodejs", "nodejs"}]

            uses?(step, "actions/setup-go@") ->
              [{"go-version", "golang", "golang"}]

            uses?(step, "actions/setup-python@") ->
              [{"python-version", "python", "python"}]

            uses?(step, "ruby/setup-ruby@") ->
              [{"ruby-version", "ruby", "ruby"}]

            uses?(step, "ocaml/setup-ocaml@") ->
              [{"ocaml-compiler", "ocaml", "ocaml"}]

            true ->
              []
          end

        for {input, tool, output} <- tool_inputs do
          expected =
            cond do
              path == @gate and name == "compatibility" ->
                assert job["needs"] == "toolchain"
                "${{ matrix.#{output} }}"

              tool == "golang" and name in ["go-conformance", "isolated-distribution"] ->
                assert Enum.any?(Enum.take(steps, index), fn earlier ->
                         earlier["id"] == "go-floor" and earlier["if"] == step["if"]
                       end)

                "${{ steps.go-floor.outputs.golang }}"

              tool == "python" and name == "python-compatibility" ->
                "${{ fromJSON(steps.toolchain.outputs.python_lanes)[matrix.lane] }}"

              true ->
                "${{ steps.toolchain.outputs.#{output} }}"
            end

          assert inputs[input] == expected, "#{path} #{name}: #{input} must come from the reader"

          unless name == "compatibility" do
            assert Enum.any?(Enum.take(steps, index), fn earlier ->
                     earlier["id"] == "toolchain" and
                       earlier["run"] == ~s|scripts/toolchain.sh >> "$GITHUB_OUTPUT"|
                   end),
                   "#{path} #{name}: read versions before installation"
          end

          assert_installed_refusal(steps, index, tool, expected, "#{path} #{name}")
        end

        if String.contains?(step["run"] || "", "mix deps.get") do
          assert step["run"] == "mix deps.get --check-locked"
        end

        if String.contains?(step["run"] || "", "rustup toolchain install") do
          assert step["run"] =~ "rustup toolchain install ${{ steps.toolchain.outputs.rust }} "

          assert step["run"] =~
                   ~s|echo "RUSTUP_TOOLCHAIN=${{ steps.toolchain.outputs.rust }}" >> "$GITHUB_ENV"|

          assert_installed_refusal(
            steps,
            index,
            "rust",
            "${{ steps.toolchain.outputs.rust }}",
            "#{path} #{name}"
          )
        end

        if String.contains?(step["run"] || "", "pip install uv") do
          assert step["run"] =~ "pip install uv==${{ steps.toolchain.outputs.uv }}"

          assert_installed_refusal(
            steps,
            index,
            "uv",
            "${{ steps.toolchain.outputs.uv }}",
            "#{path} #{name}"
          )
        end
      end
    end
  end

  defp assert_installed_refusal(steps, index, tool, expected, context) do
    prefix = if tool == "ocaml", do: "opam exec -- ", else: ""
    command = prefix <> "scripts/toolchain.sh --installed "
    setup = Enum.at(steps, index)

    assert Enum.any?(Enum.drop(steps, index + 1), fn later ->
             String.starts_with?(later["run"] || "", command) and
               String.contains?(later["run"], "#{tool}=#{expected}") and
               later["if"] == setup["if"]
           end),
           "#{context}: refuse #{tool} drift after installation"
  end

  test "compatibility lanes and SDK floors come from shared reader outputs" do
    jobs = read(@gate)["jobs"]

    assert jobs["compatibility"]["strategy"]["matrix"] ==
             "${{ fromJSON(needs.toolchain.outputs.beam_matrix) }}"

    assert jobs["toolchain"]["outputs"]["beam_matrix"] ==
             "${{ steps.compatibility.outputs.matrix }}"

    assert Enum.any?(
             jobs["toolchain"]["steps"],
             &(&1["run"] == "scripts/toolchain.sh --self-test")
           )

    outputs = toolchain_outputs()
    lanes = :json.decode(outputs["beam_lanes"])
    entries = compatibility_matrix()["include"]

    assert Enum.map(entries, &Map.take(&1, ["elixir", "otp"])) ==
             lanes ++ [%{"elixir" => outputs["elixir"], "otp" => outputs["otp"]}]

    assert Enum.map(entries, & &1["primary"]) == [false, false, true]
    assert Enum.map(entries, & &1["timeout"]) == [19, 18, 18]

    python_lanes = :json.decode(outputs["python_lanes"])
    python_job = read(".github/workflows/sdks.yml")["jobs"]["python-compatibility"]
    assert python_job["strategy"]["matrix"]["lane"] == Enum.to_list(0..(length(python_lanes) - 1))

    [go_floor] = :json.decode(outputs["golang_lanes"])

    for name <- ["go-conformance", "isolated-distribution"] do
      job = read(".github/workflows/sdks.yml")["jobs"][name]
      step = Enum.find(job["steps"], &(&1["id"] == "go-floor"))
      assert step["env"] == %{"GO_LANES" => "${{ steps.toolchain.outputs.golang_lanes }}"}

      {output, 0} =
        System.cmd("bash", ["-c", step["run"]],
          env: [{"GO_LANES", outputs["golang_lanes"]}, {"GITHUB_OUTPUT", "/dev/stdout"}]
        )

      assert String.trim(output) == "golang=#{go_floor}"
    end

    [_, declared_go] = Regex.run(~r/^go (\S+)$/m, File.read!("sdks/go/go.mod"))
    assert go_floor == declared_go <> ".0"

    [_, rust] = Regex.run(~r/^channel = "([^"]+)"$/m, File.read!("sdks/rust/rust-toolchain.toml"))
    assert outputs["rust"] == rust
  end

  test "the shared reader is byte-identical and executable" do
    digest = :crypto.hash(:sha256, File.read!("scripts/toolchain.sh"))

    assert Base.encode16(digest, case: :lower) ==
             "25bbfa023b7f031256428b498fe300fcc460988fea81277072355e4c0d933764"

    assert {"100755 " <> _, 0} =
             System.cmd("git", ["ls-files", "--stage", "scripts/toolchain.sh"])
  end

  defp toolchain_outputs do
    {output, 0} = System.cmd(Path.expand("scripts/toolchain.sh"), [])

    Map.new(String.split(output, "\n", trim: true), fn line ->
      [key, value] = String.split(line, "=", parts: 2)
      {key, value}
    end)
  end

  defp compatibility_matrix do
    outputs = toolchain_outputs()
    step = Enum.find(read(@gate)["jobs"]["toolchain"]["steps"], &(&1["id"] == "compatibility"))

    assert step["env"] == %{
             "ELIXIR" => "${{ steps.toolchain.outputs.elixir }}",
             "OTP" => "${{ steps.toolchain.outputs.otp }}",
             "BEAM_LANES" => "${{ steps.toolchain.outputs.beam_lanes }}"
           }

    {output, 0} =
      System.cmd("bash", ["-c", step["run"]],
        env: [
          {"ELIXIR", outputs["elixir"]},
          {"OTP", outputs["otp"]},
          {"BEAM_LANES", outputs["beam_lanes"]},
          {"GITHUB_OUTPUT", "/dev/stdout"}
        ]
      )

    "matrix=" <> matrix = String.trim(output)
    :json.decode(matrix)
  end

  test "each quality job runs exactly its own unconditional stage" do
    jobs = read(@gate)["jobs"]

    assert Enum.sort(Enum.filter(Map.keys(jobs), &String.starts_with?(&1, "quality-"))) ==
             Enum.sort(@quality_jobs -- ["package"])

    for name <- @quality_jobs do
      stage = String.replace_prefix(name, "quality-", "")
      steps = jobs[name]["steps"]
      assert [step] = Enum.filter(steps, &String.starts_with?(&1["run"] || "", "mix quality"))
      assert step["run"] == "mix quality.#{stage}"
      refute Map.has_key?(step, "if")
      assert Enum.count(steps, &(&1["run"] == "mix deps.get --check-locked")) == 1
    end
  end

  test "Pages deploys only when a maintainer dispatches it from the default branch" do
    pages = read(".github/workflows/pages.yml")
    assert pages["on"] == %{"workflow_dispatch" => nil}
    publish = read(".github/workflows/publish.yml")
    assert pages["jobs"]["build"]["if"] == publish["jobs"]["publish"]["if"]
    assert pages["jobs"]["deploy"]["if"] == pages["jobs"]["build"]["if"]
    assert pages["jobs"]["deploy"]["needs"] == "build"
    assert_default_branch_first(pages["jobs"]["build"])
    assert_default_branch_first(pages["jobs"]["deploy"])
    assert pages["jobs"]["deploy"]["environment"]["name"] == "github-pages"
  end

  test "Hex publication is dispatch-only, maintainer-restricted and environment-scoped" do
    workflow = read(".github/workflows/publish.yml")
    assert workflow["on"] == %{"workflow_dispatch" => nil}
    assert workflow["permissions"] == %{"contents" => "read"}
    assert Enum.sort(Map.keys(workflow["jobs"])) == ["publish", "published-livebooks"]
    job = workflow["jobs"]["publish"]
    assert job["environment"] == "publish"

    assert job["if"] ==
             ~s|contains(fromJSON('["corepay","palermo-git"]'), github.actor) && contains(fromJSON('["corepay","palermo-git"]'), github.triggering_actor)|

    assert_default_branch_first(job)
    refute Map.has_key?(workflow, "env")
    refute Map.has_key?(job, "env")
    assert job["timeout-minutes"] == 5
  end

  test "the attested package passed every quality stage and its archive was checked" do
    ci = read(@gate)
    assert MapSet.new(ci["jobs"]["attest"]["needs"]) == MapSet.new(@quality_jobs)
    assert ci["jobs"]["attest"]["with"]["version"] == "${{ needs.package.outputs.version }}"

    package = ci["jobs"]["package"]
    assert package["outputs"]["version"] == "${{ steps.archive.outputs.version }}"
    steps = package["steps"]
    quality = Enum.find_index(steps, &(&1["run"] == "mix quality.package"))
    archive = Enum.find_index(steps, &String.contains?(&1["run"] || "", "mix hex.build"))

    inspect_package =
      Enum.find_index(steps, &String.contains?(&1["run"] || "", "check_package.exs"))

    assert quality != nil and archive != nil and quality < archive
    assert is_integer(inspect_package) and archive < inspect_package

    refute Map.has_key?(Enum.at(steps, quality), "if"),
           "mix quality.package must run on every event"

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

      assert {ref, status == 0} == {ref, ref == "refs/heads/main"}
    end
  end
end
