Code.require_file("corpus_verdicts.exs", __DIR__)

alias BoundedAuthorityProtocol.CorpusVerdicts

path = Path.expand("../priv/conformance/verdict-digests.json", __DIR__)
bytes = CorpusVerdicts.manifest()

case System.argv() do
  ["--write"] -> File.write!(path, bytes)
  [] -> if File.read!(path) != bytes, do: raise("stale corpus verdict-digests.json")
  _ -> raise "usage: mix run scripts/regen_verdict_digests.exs [--write]"
end

IO.puts("corpus verdict digests: ok corpora=9")
