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

  # Glob patterns built with "/" literals (Path.join(dir, "**/*.json")) stay mixed-separator
  # on Windows, and erlang's wildcard does not match them; normalize to the native separator.
  def wildcard(pattern, opts \\ []) do
    if windows?() do
      pattern |> String.replace("/", "\\") |> Path.wildcard(opts)
    else
      Path.wildcard(pattern, opts)
    end
  end
end
