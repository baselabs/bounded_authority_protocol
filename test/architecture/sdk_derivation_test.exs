defmodule BoundedAuthorityProtocol.SdkDerivationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)

  for {sdk, checker, command, source, comment} <- [
        {"python", "purity_check.py", "python3", "src/bounded_authority_verifier/probe.py", "#"},
        {"rust", "purity_check.sh", "sh", "src/probe.rs", "//"},
        {"go", "purity_check.sh", "sh", "probe.go", "//"}
      ] do
    @sdk sdk
    @checker checker
    @command command
    @source source
    @comment comment

    test "#{sdk} derivation guard scans the entire SDK including itself" do
      root =
        Path.join(
          System.tmp_dir!(),
          "bap-derivation-#{@sdk}-#{System.unique_integer([:positive])}"
        )

      on_exit(fn -> File.rm_rf!(root) end)
      checker = Path.join(root, "tools/#{@checker}")
      File.mkdir_p!(Path.dirname(checker))
      File.cp!(Path.join([@root, "sdks", @sdk, "tools", @checker]), checker)
      source = Path.join(root, @source)
      File.mkdir_p!(Path.dirname(source))
      File.write!(source, "#{@comment} Pure source fixture\n")
      readme = Path.join(root, "README.md")

      File.write!(
        readme,
        "BoundedAuthorityProtocol is the contract namespace (ex. in diagnostics).\n"
      )

      assert {_, 0} = run(@command, checker)

      paths = [
        @source,
        "tests/citation.txt",
        "tools/citation.txt",
        "docs/citation.md",
        "README.md",
        ".hidden/citation",
        "tools/#{@checker}"
      ]

      for path <- paths,
          citation <- [
            "lib/bounded_authority_protocol/v1/grant.ex",
            "grant.ex",
            "check.exs",
            "mix.exs"
          ] do
        target = Path.join(root, path)
        File.mkdir_p!(Path.dirname(target))
        original = File.read(target)

        contents =
          case original do
            {:ok, contents} -> contents
            {:error, :enoent} -> ""
          end

        try do
          File.write!(target, contents <> "\n#{@comment} #{citation}\n")
          {output, status} = run(@command, checker)
          assert status == 1, "#{@sdk} accepted #{citation} in #{path}: #{output}"
          assert output =~ "#{path}:"
          assert output =~ "reference source citation"
        after
          case original do
            {:ok, contents} -> File.write!(target, contents)
            {:error, :enoent} -> File.rm!(target)
          end
        end
      end

      assert {_, 0} = run(@command, checker)
    end
  end

  defp run(command, checker) do
    System.cmd(command, [checker], stderr_to_stdout: true)
  end
end
