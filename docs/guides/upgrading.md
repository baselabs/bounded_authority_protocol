# Upgrading to 1.0

Package 1.0.0 is the first release under the 1.x stability contract: from here on, anything that
would break your code waits for 2.0.0, with two exceptions a minor release may carry. A soundness
repair can reject inputs that no conforming producer emits, and a raised Elixir or Erlang/OTP floor
is announced in the changelog ([API stability and versioning](api-stability.md)). This page lists what changes when you move
from a 0.x release to 1.0, then the extra steps for older starting points. The
[changelog](../../CHANGELOG.md) has the full history.

## Move the requirement

```elixir
defp deps do
  [{:bounded_authority_protocol, "~> 1.0"}]
end
```

`~> 1.0` admits every 1.x release. A 0.x requirement such as `~> 0.9.1` never selects 1.0, so
the change is explicit. Then run `mix deps.update bounded_authority_protocol` and the packaged
corpora ([Recipes](recipes.md#run-every-packaged-corpus)).

## What changes in 1.0

No wire byte changes, and every certified corpus keeps its cases and verdicts. These changes
can affect your code:

1. **Float zero in selectors (erratum 6).** On every contract-major, grant decode and
   verification reject a grant whose `equals` value or `one_of` member holds a float-tagged
   zero (`0.0`, `-0.0`, or an underflowing literal), and the grant producers refuse a
   float-tagged whole-number selector value such as `{:float, 2.0}`. Conforming verifiers
   disagreed about these values, and no conforming producer emits them.
   **Action:** tag whole numbers `{:integer, n}` in selectors. If you stored grants you did not
   produce with this package, decode them once; one that no longer decodes held such a value and
   must be re-issued. See the [errata registry](../errata.md).
2. **Conformance internals are hidden.** `BoundedAuthorityProtocol.Conformance.Corpus`,
   `Runner`, and `Report` are no longer documented or covered by the stability contract.
   **Action:** call `BoundedAuthorityProtocol.Conformance.Cli.run/1`, which returns the exit
   status (`0`, `1`, or `2`), or run the `bounded_authority_conformance` command. Do not call
   `Conformance.Cli.Main.main/1`; it halts the VM.
3. **The conformance CLI is stricter.** It reads only the files a corpus index names, refuses
   symbolic links and over-size files, checks that it ran every case the certified index lists
   exactly once, verifies the three sibling-profile corpora (local-loopback, role attestation,
   content assertion), exits `0` on `--help`, writes one line to standard error on a failure, and
   ends its report with a newline. Its flags, exit statuses, and report fields are now part of
   the stability contract.
4. **`Bounds` fields default to the maxima.** `%Bounds{}` equals `Bounds.maximum()`, and
   `%Bounds{depth: 8}` is a one-field tightening. Code that built the struct with every field
   still works; `new/1`, `maximum/0`, and `coerce/1` are unchanged.
5. **`inspect/2` redacts credentials.** Inspecting `Credentials`, `ExpectedRequest`, proofs,
   decoded proofs, or a `SigningInput` shows `:redacted` in place of the compact credentials,
   the cast arguments, the nonce, and the signing bytes. If your tests matched on inspected
   output, match on the fields instead. Redaction protects against accidental logging only;
   reading a field still returns its value.
6. **The thumbprint helpers are documented.** `V1.Jwk.public_key_thumbprint_raw/2`,
   `V1.Jwk.thumbprint_raw/2`, `V3.EcJwk.public_key_thumbprint_raw/2`, and
   `V3.EcJwk.thumbprint_raw/2` are now part of the stable surface. Code that already used them
   needs no change.
7. **The request-digest projection is bounded while it walks.** `request_digest/3`,
   `proof_signing_input/2`, and `check_envelope/2` stop at the depth, node, container, and
   string budgets as they project the arguments, instead of after. The accepted set and every
   digest byte are unchanged; an oversized argument tree is rejected without being walked.

Every public function now has a typespec and every public struct documents its fields, which
helps Dialyzer and your editor but changes no behavior.

## From older releases

Apply every row from your starting release down to 1.0.

| You are on | Also do this |
|---|---|
| 0.8.x | ES256 compact assembly refuses a high-S or out-of-range signature. If you sign through a KMS or an HSM and assemble yourself, convert with `Es256.der_to_raw/1`, then `Es256.normalize_low_s/1`, before `assemble_compact/2` ([Recipes](recipes.md#es256-from-a-kms-or-hsm)). |
| 0.7.x or earlier | Every Ed25519 verification applies the strict rule: canonical encodings, no small-order key or `R`, `S` below the group order. Before upgrading, run `Ed25519.acceptable_public_key?/1` and `Ed25519.torsion_free?/1` over every stored trusted key, enrolled holder key, attestation key, and archived key chain, and treat a failure as a compromise. From then on, call `torsion_free?/1` at enrollment, at trust install, and before revocation comparisons. Producers refuse a placeholder key such as 32 zero bytes. These releases are retired on Hex. |

## Checking that you are unaffected

1. Move the requirement and keep `mix.lock` committed, so the exact release is recorded.
2. Run every packaged corpus from your project
   ([Recipes](recipes.md#run-every-packaged-corpus)). Exit `0` for each means the installed
   release agrees with every certified corpus.
3. If your own tests pin a corpus index digest, it does not change in 1.0.
4. Run your integration tests, including the rejection paths, and fix any test that matched on
   `inspect/2` output.

## After 1.0

Read the changelog's entry for each minor release you adopt. A minor release may add a
contract-major, a sibling profile, functions, optional arguments, defaulted struct fields, or a
soundness repair recorded in the errata registry, and may raise the Elixir or Erlang/OTP floor;
none requires a code change. A 2.0.0 release would say what to change.
