shallow =
  case System.cmd("git", ["rev-parse", "--is-shallow-repository"], stderr_to_stdout: true) do
    {output, 0} ->
      output

    {output, _status} ->
      raise "the test suite reads this repository's tracked files and history and must run " <>
              "in a git checkout; git said: " <> String.trim(output)
  end

exclude =
  if String.trim(shallow) == "true" do
    if System.get_env("BAP_REQUIRE_FULL_HISTORY") == "1" do
      raise "BAP_REQUIRE_FULL_HISTORY=1 requires a complete checkout; fetch-depth must be 0"
    end

    IO.puts(
      :stderr,
      "Excluding :git_history tests: shallow checkout has incomplete repository history; CI requires fetch-depth: 0"
    )

    [:git_history]
  else
    []
  end

ExUnit.start(exclude: exclude)
