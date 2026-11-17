defmodule BoundedAuthorityProtocol.BuildPath do
  @moduledoc false

  # Mix owns the active project's path. Standalone tools and other checkouts use
  # the same environment precedence without consulting the active project's cache.
  def resolve(root, environment \\ nil) do
    root = Path.expand(root)
    mix? = Process.whereis(Mix.ProjectStack) != nil and Mix.Project.get() != nil

    environment =
      environment || if(mix?, do: to_string(Mix.env()), else: System.get_env("MIX_ENV", "dev"))

    if mix? and root == File.cwd!() and environment == to_string(Mix.env()) do
      Mix.Project.build_path()
    else
      case System.get_env("MIX_BUILD_PATH") do
        nil -> Path.join(storage_root(root), environment)
        path -> Path.expand(path, root)
      end
    end
  end

  def storage_root(root) do
    Path.expand(
      System.get_env("MIX_BUILD_PATH") || System.get_env("MIX_BUILD_ROOT") || "_build",
      root
    )
  end

  def storage_roots(root) do
    Enum.uniq([Path.expand("_build", root), storage_root(root)])
  end

  # A scratch checkout must never inherit an absolute path into its source checkout.
  def isolated(root, environment), do: Path.join([root, "build", environment])
end
