Code.require_file("../tools/architecture_gate.exs", __DIR__)

alias BoundedAuthorityProtocol.ArchitectureGate

{options, arguments, invalid} =
  OptionParser.parse(System.argv(),
    strict: [root: :string, skip_compiled: :boolean]
  )

if arguments != [] or invalid != [] do
  IO.puts(:stderr, "usage: elixir scripts/check_architecture.exs [--root PATH] [--skip-compiled]")
  System.halt(2)
end

root = options[:root] || Path.expand("..", __DIR__)
violations = ArchitectureGate.check(root, compiled: options[:skip_compiled] != true)

case violations do
  [] ->
    IO.puts("architecture boundary passed")

  findings ->
    IO.puts(:stderr, ArchitectureGate.format(findings))
    System.halt(1)
end
