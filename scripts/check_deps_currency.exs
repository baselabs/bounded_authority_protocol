# Dependency currency check — the latest-first policy gate (ADR 0032).
#
# Elixir, not shell, on purpose: this gate runs inside `mix quality`, and a declared
# gate must hold the tri-platform build bar (a POSIX script inside a gate is dead on
# Windows). `mix` is spawned as a subprocess — through `cmd /c` on Windows, where
# mix.bat cannot be executed by System.cmd directly.
#
# Classification is on the RENDERED table, never on the exit code (mix hex.outdated
# exits nonzero BOTH on drift and on lookup failure):
#   "Update possible"      -> resolvable drift  -> exit 1, packages named
#   "Update not possible"  -> resolver-rejected -> reported with each package's
#                             requirement chain; an upstream pin is not this
#                             repository's drift and does not fail the gate
#   no table rendered      -> currency state UNVERIFIED -> exit 1
# Rows are padded with trailing whitespace, so status matching is anchored on \s*$
# — a hard $ would fail open on the padded rows.
#
# Both the direct-dependency table and `--all` (transitives) are classified: a
# resolvable transitive drift is drift. Anything deliberately not at latest carries
# an inline reason next to its requirement in mix.exs.

defmodule BoundedAuthorityProtocol.CheckDepsCurrency do
  @moduledoc false

  @table_header ~r/^Dependency\s+(Only\s+)?Current\s+Latest/m
  @drift ~r/^.*Update possible\s*$/m
  @rejected ~r/^.*Update not possible\s*$/m
  @noise ~r/authentication session|hex\.user auth/

  def run! do
    statuses =
      [direct: [], all: ["--all"]] |> Enum.map(fn {label, extra} -> classify(label, extra) end)

    if Enum.any?(statuses, &(&1 != :ok)) do
      # exit({:shutdown, 1}) instead of System.halt/1: it flushes ports, so the stderr
      # package list printed just above is never truncated.
      exit({:shutdown, 1})
    else
      IO.puts(
        "check_deps_currency: no resolvable drift (direct or transitive); pins are upstream of this gate"
      )
    end
  end

  defp classify(label, extra) do
    out = mix_outdated(extra)

    unless Regex.match?(@table_header, out) do
      IO.puts(
        :stderr,
        "check_deps_currency [#{label}]: no dependency table rendered — currency state unverified:"
      )

      IO.puts(:stderr, out)
      :unverified
    else
      report(label, out)
    end
  end

  defp report(label, out) do
    drift = Regex.scan(@drift, out) |> List.flatten()
    rejected = Regex.scan(@rejected, out) |> List.flatten()

    unless drift == [] do
      IO.puts(
        :stderr,
        "check_deps_currency [#{label}]: RESOLVABLE DRIFT (latest-first policy, ADR 0032):"
      )

      Enum.each(drift, &IO.puts(:stderr, &1))
    end

    unless rejected == [] do
      IO.puts(
        :stderr,
        "check_deps_currency [#{label}]: resolver-rejected updates (requirement chains):"
      )

      Enum.each(rejected, &IO.puts(:stderr, &1))

      Enum.each(rejected, fn line ->
        pkg = line |> String.split() |> List.first()
        chain = mix_outdated([pkg])

        chain
        |> String.split("\n")
        |> Enum.reject(&Regex.match?(@noise, &1))
        |> Enum.each(&IO.puts(:stderr, &1))
      end)
    end

    if drift == [], do: :ok, else: :drift
  end

  defp mix_outdated(extra) do
    {out, _status} = spawn_mix(["hex.outdated" | extra])
    out
  end

  defp spawn_mix(args) do
    if match?({:win32, _}, :os.type()) do
      System.cmd("cmd", ["/s", "/c", "mix" | args], stderr_to_stdout: true)
    else
      System.cmd("mix", args, stderr_to_stdout: true)
    end
  end
end

BoundedAuthorityProtocol.CheckDepsCurrency.run!()
