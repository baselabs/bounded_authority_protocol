defmodule BoundedAuthorityProtocol.Conformance.Cli.Main do
  @moduledoc false

  # Escript entry point. Two responsibilities: hand argv to the pure-judgment CLI core and halt
  # with its exit status. `System.halt/1` is the ONLY non-pure call and lives here, never in the
  # verification path (the architecture gate pins this exact-path/exact-function carve-out).

  alias BoundedAuthorityProtocol.Conformance.Cli

  def main(argv) do
    System.halt(Cli.run(argv))
  end
end
