defmodule BoundedAuthorityProtocol.TestSupport.Portable do
  @moduledoc """
  Filesystem helpers for tests.

  `tmp_dir!/1` replaces `mktemp`-style scratch roots; `ls_r/1` walks a
  tree without the glob engine.
  """

  def tmp_dir!(label) do
    Path.join(System.tmp_dir!(), "#{label}-#{System.unique_integer([:positive])}")
  end

  # Recursive enumeration WITHOUT the glob engine: erlang's wildcard returned [] on the
  # Windows runner for both forward- and backslash patterns under its short-name TEMP
  # root, while plain File.ls!/File read/write worked everywhere. The walk lists every
  # entry, hidden files included (the match_dot case); callers filter by suffix as needed.
  def ls_r(path) do
    case File.ls!(path) do
      names when is_list(names) ->
        Enum.flat_map(names, fn name ->
          full = Path.join(path, name)
          if File.dir?(full), do: ls_r(full), else: [full]
        end)
    end
  end
end
