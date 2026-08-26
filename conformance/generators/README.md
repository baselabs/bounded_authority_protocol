# Conformance corpus generator (re-derivability tooling)

This directory is authoring tooling for the v1 conformance corpus — it is NOT a conformance
runner and is not part of the published package. The runners live under `conformance/*.mjs`,
`sdks/*/`, and the Elixir verifier CLI.

## What is frozen and what is derived

The corpus's signed fixtures (every file under `cases/`, including the `.raw` byte sidecars)
are **frozen, authoritative inputs**. They were minted with ephemeral in-memory Ed25519 keys at
authoring time; the throwaway mint script was removed afterward, as the vectors' provenance
blocks record. No tool can re-mint them — fresh keys would produce different bytes — and none
is provided here.

Everything else is **mechanically derived** and byte-verified by this tool:

- `index.json` — per-file SHA-256 digests, per-file case counts, the total, the applicability
  matrix, and the files set, all rebuilt from the frozen case files, the revision sidecar, and
  the curated inputs below.
- `revision.json` — the monotone corpus revision integer and its provenance note.

Two blocks of the index are **curated inputs**, shipped here so the rebuild is complete:
`curated-inputs.json` carries the n_a applicability reasons (prose, not derivable from case
bytes) and the public-key fingerprint census (already machine-verified against the corpus by
every runner's two-boundary census; the generator takes it as an input rather than duplicating
key-discovery logic).

## Usage

```sh
node conformance/generators/build_corpus.mjs --verify            # shipped corpus == rebuild
node conformance/generators/build_corpus.mjs --rebuild-index     # rewrite index.json from inputs
node conformance/generators/build_corpus.mjs --bump-revision --note "why this revision changed"
```

`--verify` exits nonzero on any drift: a case byte, a digest, a count, an applicability cell,
a tamper case whose verbatim artifact disagrees with the re-derived base-with-one-flip, or a
stale index/sidecar.

## Amending the corpus (the atomic-landing template, ADR 0019)

A corpus amendment is ONE commit that carries: the case-file changes, the rebuilt `index.json`
(`--rebuild-index` or `--bump-revision`), the re-vendored `sdks/{rust,go}/conformance/corpus/`
snapshots, all six certified-index-SHA pins rotated in the same change
(`elixir scripts/regen_corpus_digests.exs --write`), and the consumer documentation that cites
the count or digest. The revision integer in `revision.json` is the citation target for
corpus-dependent documents (it replaced the vacuous `format`-string citation — the format value
never changes across revisions, so it could not detect drift).

## Provenance

This generator was reconstructed at the revision-sidecar landing (repository history records
the exact commit); the original ephemeral mint script never lived in the repository.
