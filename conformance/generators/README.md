# Conformance corpus generator (re-derivability tooling)

This directory contains authoring tooling for the v1 conformance corpus, not a conformance
runner and is not part of the published package. The runners live under `conformance/*.mjs`,
`sdks/*/`, and the Elixir verifier CLI.

## What is frozen and what is derived

The corpus's signed fixtures (every file under `cases/`, including the `.raw` byte sidecars)
are **frozen, authoritative inputs**. They were minted with ephemeral in-memory Ed25519 keys at
authoring time; the throwaway mint script was removed afterward, as the vectors' provenance
blocks record. Fresh keys would produce different bytes, so no tool can re-mint them and none
is provided here.

Everything else is **mechanically derived** and byte-verified by this tool:

- `index.json` records per-file SHA-256 digests, per-file case counts, the total, the applicability
  matrix, and the files set, all rebuilt from the frozen case files, the revision sidecar, and
  the curated inputs below.
- `revision.json` records the monotone corpus revision integer and its provenance note.

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

## Amending the corpus (the atomic-landing template)

Regenerate the expected verdict manifest after rebuilding the corpus, then copy the complete
`priv/conformance/` tree into each SDK and rotate every index pin with the regeneration tool.
The input hashes and expected verdict digest must describe the same rebuilt cases.

A corpus amendment is one commit that carries: the case-file changes, the rebuilt `index.json`
(`--rebuild-index` or `--bump-revision`), the re-vendored `sdks/{python,rust,go}/conformance/priv/conformance/`
snapshots, all nine corpora and every SDK certified-index-SHA pin rotated in the same change
using the digest regeneration tool, and the consumer documentation that cites
the count or digest. The revision integer in `revision.json` is the citation target for
corpus-dependent documents (it replaced the vacuous `format`-string citation, whose format value
never changes across revisions, so it could not detect drift).

## Provenance

This generator was reconstructed at the revision-sidecar landing (repository history records
the exact commit); the original ephemeral mint script never lived in the repository.

The complete Hex corpus tree is vendored into each SDK, including schemas, focused vectors,
and the sibling verdict manifest. Regeneration and gates cover all nine corpora. The
[verdict digest contract](../../docs/design/corpus-verdict-digests.md) specifies expected
outcome projections and index order. CI runs every generator's `--verify` mode; signed
content-assertion fixtures are verified without minting replacement keys or signatures.
