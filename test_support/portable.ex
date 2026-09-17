defmodule BoundedAuthorityProtocol.TestSupport.Portable do
  @moduledoc """
  Platform-portable process invocation for tests.

  On Windows, `mix`, `elixir`, and `escript` are `.bat`/`.cmd` shims that
  `System.cmd/3` (CreateProcess) cannot execute directly; they must run
  through `cmd /c`. `cmd/3` centralizes that so the library contract
  (clone, compile, test) holds on a Windows checkout.

  `windows?/0` gates the few tests whose mechanism has no Windows
  equivalent (chmod-based unreadability, POSIX shell guards); each such
  site documents its carve-out. `tmp_dir!/1` replaces `mktemp`-style
  scratch roots.
  """

  def windows?, do: match?({:win32, _}, :os.type())

  def cmd(program, args, opts \\ []) do
    if windows?() do
      System.cmd("cmd", ["/s", "/c", program | args], opts)
    else
      System.cmd(program, args, opts)
    end
  end

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

  # Corpus.load and the declared corpora use "/"-separated keys; Path.relative_to joins
  # with the native separator on Windows, so map keys built from real paths must be
  # normalized before they meet a declared name.
  def to_posix(path), do: String.replace(path, "\\", "/")
end
