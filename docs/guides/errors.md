# Errors and outcomes

Most protocol operations return the same closed refusal for invalid caller input, malformed
bytes, exceeded ceilings, and failed cryptographic or context checks. The action approval
verifier returns [ordered local diagnostics](../../spec/bap-action-approval-v1.md#4-approval-verification)
for operators. Every presenter-facing verification failure uses the uniform `invalid` result.

| Public family | Refusal | Meaning and cause | Remedy |
|---|---|---|---|
| Grant and proof producers, assembly and decoders in contract-major 1/contract-major 2/contract-major 3 | `{:error, :invalid}` | Wrong shape, unknown member/profile, noncanonical or over-limit bytes/signature | Correct the producer and exact selected profile; keep bounds closed |
| Grant verification and envelope checks | `{:error, :invalid}` | Bytes do not satisfy trusted keys, expected context, selectors or time | Compare your own inputs using [troubleshooting](troubleshooting.md); never broaden expectations to pass |
| Chain, anchor, transition and archive producers/verifiers | `{:error, :invalid}` | Missing/reordered/changed evidence or wrong caller boundaries/key history/object version | Supply complete raw evidence and independently trusted expected boundaries |
| Local-loopback, role and custody attestation, and EdDSA and ES256 content-assertion operations | `{:error, :invalid}` | Wrong explicit profile, nonce, custody class, context, attestor window, digest or lineage relation | Select the right profile before parsing and correct the exact expected inputs |
| Action approval record encoding and decoding | `{:error, :invalid}` | Invalid or over-limit record, or noncanonical wire bytes | Use the exact canonical record and its effective bounds |
| Action approval verification | `{:error, code}` | Value-free diagnostic for the first failed stage | Use the code locally and return uniform `invalid` to presenters |
| JSON, JCS, base64url, URI, JWK, bounds construction/coercion and digest primitives | `{:error, :invalid}` | Invalid type/tag/encoding, duplicate member or exceeded ceiling | Pass valid tagged values and canonical encodings; tighten only known bounds |
| `ContentAssertion.V1.verify_successor/3` | `{:error, :invalid}` | Supplied facts are inconsistent, not a provenance judgment | Verify both assertions, compare forward generations, maintain durable high-water state |
| Crypto predicates | `false` | Invalid key/signature or failed predicate | Enroll acceptable keys; use the selected suite and canonical signature form |
| ES256 conversion/normalization | `{:error, :invalid}` | Invalid DER, width or scalar range | Convert a valid signer result and normalize low S before assembly |

`Bounds.maximum/0` has no refusal. Successful tuple operations return `{:ok, value}`;
`verify_successor/3` returns `:ok`. See the [complete result matrix](api-stability.md#result-families).
The SDK spellings are Python `Err(InvalidError())`, Go `ErrInvalid`, and Rust `Err(Invalid)`;
crypto predicates use booleans. Verifier failures carry no partial facts.

## CLI exit statuses

| Status | Meaning | Remedy |
|---|---|---|
| `0` | Complete certified agreement, or `--help` / `--version` | Require the complete report when claiming conformance; help/version alone is not evidence |
| `1` | Corpus, execution, certification or I/O refusal | Correct the named class below; retain refusal until every case agrees |
| `2` | Usage error (missing `--corpus`, unknown flag or missing value) | Use `bounded_authority_conformance --corpus DIR [--report PATH]` |

The following are every closed CLI diagnostic class, not protocol credential error values.
Each message omits paths, case ids and corpus bytes. Stderr wording is not a stable API.

| CLI class | Meaning / cause | Remedy |
|---|---|---|
| `:unreadable` | Cannot read the corpus directory or one of its named files | Check permissions and reinstall the certified corpus; never suppress read failures. |
| `:not_regular` | The corpus directory holds a symbolic link or another non-regular entry | Use the original regular files; remove links and special entries. |
| `:unlisted` | The corpus directory holds a file the index does not name | Use the exact packaged directory; do not add files to a certified corpus. |
| `:oversized` | A corpus file exceeds the 1 MiB limit or the directory exceeds 4096 entries | Use the packaged corpus within the file and entry limits. |
| `:index` | The corpus index is missing, malformed or names an unsafe path | Restore the packaged index and safe relative paths. |
| `:integrity` | The corpus failed integrity verification | Reinstall the exact package; investigate changed input bytes. |
| `:uncertified` | The corpus is not a certified corpus for this release | Use the corpus certified by the installed release. |
| `:report` | The report could not be written | Choose a writable output directory and adequate storage. |
| `:disagreement` | The corpus run did not reach complete agreement | Do not claim conformance; inspect the report and correct the implementation. |

## Host failures

Unknown trusted key, unavailable revocation state, exhausted replay storage, and host policy
refusal are host outcomes. The service notebook's `:unknown_key`, `:replayed`, `:accepted`, and
`:rejected` labels illustrate host logic. The action approval verifier also uses `:unknown_key` as a local diagnostic. Keep your host's
closed error contract separate and return a uniform refusal when verification fails.

A malformed invocation of a language's function itself (for example the wrong arity) is a
programming error. Do not catch all exceptions and label them `:invalid`; fix the integration.
