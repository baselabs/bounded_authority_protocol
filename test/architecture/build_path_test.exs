Code.require_file("../../tools/build_path.exs", __DIR__)

defmodule BoundedAuthorityProtocol.BuildPathTest do
  use ExUnit.Case, async: false

  alias BoundedAuthorityProtocol.BuildPath

  test "the active Mix project owns its cached build path" do
    assert BuildPath.resolve(File.cwd!()) == Mix.Project.build_path()
  end

  test "standalone tools resolve paths without a running Mix project" do
    root = Path.join(System.tmp_dir!(), "bap-standalone-build")
    helper = Path.expand("../../tools/build_path.exs", __DIR__)

    code =
      "IO.puts(BoundedAuthorityProtocol.BuildPath.resolve(System.fetch_env!(\"BAP_BUILD_TEST_ROOT\")))"

    assert {output, 0} =
             System.cmd("elixir", ["-r", helper, "-e", code],
               env: [
                 {"BAP_BUILD_TEST_ROOT", root},
                 {"MIX_ENV", "prod"},
                 {"MIX_BUILD_ROOT", "custom-build"},
                 {"MIX_BUILD_PATH", nil}
               ],
               stderr_to_stdout: true
             )

    assert String.trim(output) == Path.join(root, "custom-build/prod")
  end

  test "standalone checkouts share environment precedence and scratch builds stay isolated" do
    keys = ["MIX_BUILD_PATH", "MIX_BUILD_ROOT", "MIX_ENV"]
    original = Enum.map(keys, &{&1, System.get_env(&1)})

    on_exit(fn ->
      Enum.each(original, fn
        {key, nil} -> System.delete_env(key)
        {key, value} -> System.put_env(key, value)
      end)
    end)

    root = Path.join(System.tmp_dir!(), "bap-build-path")
    Enum.each(keys, &System.delete_env/1)
    assert BuildPath.resolve(root, "test") == Path.join(root, "_build/test")
    assert BuildPath.resolve(root) == Path.join(root, "_build/#{Mix.env()}")
    System.put_env("MIX_BUILD_ROOT", "custom")
    assert BuildPath.resolve(root, "test") == Path.join(root, "custom/test")
    System.put_env("MIX_BUILD_ROOT", Path.join(root, "absolute"))
    assert BuildPath.resolve(root, "prod") == Path.join(root, "absolute/prod")
    System.put_env("MIX_BUILD_PATH", "explicit")
    assert BuildPath.resolve(root, "test") == Path.join(root, "explicit")
    assert BuildPath.storage_root(root) == Path.join(root, "explicit")
    System.put_env("MIX_BUILD_PATH", Path.join(root, "absolute-explicit"))
    assert BuildPath.resolve(root, "test") == Path.join(root, "absolute-explicit")
    assert BuildPath.isolated(root, "test") == Path.join(root, "build/test")
  end
end
