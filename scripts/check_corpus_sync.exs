Code.require_file("corpus_distribution.exs", __DIR__)

alias BoundedAuthorityProtocol.CorpusDistribution

CorpusDistribution.with_package!(&CorpusDistribution.check!/1)
IO.puts("corpus sync gate: ok SDKs=3, whole Hex subtree byte-identical")
