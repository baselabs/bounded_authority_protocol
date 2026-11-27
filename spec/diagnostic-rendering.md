# BAP diagnostic rendering

This is the language-neutral diagnostic display contract for decoded BAP values and fully
redacted facts. It defines display bytes, not a wire encoding, a generic serialization format,
or evidence of verification, trust, or authorization. It applies to contract-majors 1, 2, and 3
and the role-attestation, holder custody attestation, and content-assertion sibling profiles.

## Diagnostic rendering

Implementations MUST produce the UTF-8 bytes specified below regardless of language version,
caller display limits, line width, pretty printing, numeric base, or formatting flags
when rendering through the implementation's diagnostic display protocol. In Elixir, this
contract binds rendering through the `Inspect` protocol. `inspect(value, structs: false)`
bypasses that protocol and prints raw fields; it MUST NEVER be used to log decoded proofs,
facts, or other redacted values.
There are no line breaks or indentation except escaped characters inside quoted strings.
Names, punctuation, spaces, field order, and ellipses are significant.

An implementation renders the value kinds it exposes according to this contract. An
implementation exposing only fully redacted facts and decoded content assertions implements
only the `redacted` forms; it need not expose structural decoded values.

### Names and field order

For each `N` in `1`, `2`, and `3`, the structural names are
`BoundedAuthorityProtocol.VN.DecodedGrant` and `BoundedAuthorityProtocol.VN.Operation`,
with `N` replaced by that decimal digit. The decoded grant fields, in order, are:

```text
version, key_id, issuer, grant_id, audiences, issued_at, not_before, expires_at,
holder_thumbprint, operations, verification
```

An operation's fields are `name, selectors`. Selectors are values, not additional named
structs: `:all`; `{:equals, path, value}`; `{:one_of, path, values}`; and, in majors 2 and 3,
`{:lte, path, value}` and `{:gte, path, value}`.
Paths and ordered tagged JSON members preserve their decoded order and types.

The structural role-attestation name is
`BoundedAuthorityProtocol.RoleAttestation.V1.DecodedAttestation`. Its fields are:

```text
version, attestor_key_id, jti, key_id, public_key, role, nbf, exp, verification
```

The structural holder custody attestation name is
`BoundedAuthorityProtocol.HolderCustodyAttestation.V1.DecodedAttestation`. Its fields are:

```text
version, attestor_key_id, jti, key_id, public_key, custody_class, nbf, exp, verification
```

The fixed proof names are `BoundedAuthorityProtocol.VN.DecodedProof`, with the same three
substitutions for `N`. Their fields are:

```text
version, proof_id, method, target_uri, issued_at, nonce, invocation_id, operation,
grant_hash, request_hash, holder_public_key, holder_thumbprint, verification
```

The fully redacted names are `BoundedAuthorityProtocol.VN.GrantFacts`,
`BoundedAuthorityProtocol.VN.EnvelopeFacts`, `BoundedAuthorityProtocol.VN.ChainFacts`,
`BoundedAuthorityProtocol.VN.AnchorFacts`, `BoundedAuthorityProtocol.VN.KeyTransitionFacts`,
and `BoundedAuthorityProtocol.VN.AnchoredExportFacts`, for those same three majors, plus
`BoundedAuthorityProtocol.RoleAttestation.V1.AttestationFacts`,
`BoundedAuthorityProtocol.HolderCustodyAttestation.V1.AttestationFacts`,
`BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts`,
`BoundedAuthorityProtocol.ContentAssertion.V1.DecodedContentAssertion`,
`BoundedAuthorityProtocol.ContentAssertion.ES256.V1.ContentAssertionFacts`,
`BoundedAuthorityProtocol.ContentAssertion.ES256.V1.DecodedContentAssertion`,
`BoundedAuthorityProtocol.ActionApproval.V1.Record`, and
`BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts`.

### Grammar and redaction

In this grammar, quoted punctuation is literal, `name` is one of the full names above,
`key` is a field name or selector, tagged JSON, or diagnostic atom name without its colon,
and `sequence` is an ordered
comma-and-space separated sequence. An empty sequence has no bytes.

```text
struct       = "%" name "{" fields "}"
proof        = "#" name "<" fields ">"
redacted     = "#" name "<redacted>"
field        = key ": " value
fields       = sequence of field, optionally terminated by "..."
list         = "[" sequence of value "]"
keyword-list = "[" fields "]"
tuple        = "{" sequence of value "}"
binary       = "<<" sequence of decimal byte ">>"
unrenderable = "#unrenderable"
atom         = ":" key
value        = struct / list / keyword-list / tuple / binary / quoted-string /
               decimal-integer / decimal-float / atom / "nil" / "true" / "false" / unrenderable
```

All facts, decoded content assertions and approval records use exactly
`redacted`, with no fields. An approval success wrapper renders as
`{:ok, #BoundedAuthorityProtocol.ActionApproval.V1.VerifiedApprovalFacts<redacted>}`.
An SDK host-helper success renders as
`#BoundedAuthorityProtocol.ActionApproval.V1.Approved<redacted>`.
Host-local failed results render as `{:error, :code}` with the exact specified
reason atom substituted for `code`. Presenter-facing failed results render
as `{:error, :invalid}`. These forms serialize statically, including when
used in logs. They expose no nested record or assertion fields.
Proofs use `proof`. A proof nonce is `nil` if absent and exactly `:redacted` whenever
present, regardless of its contents. Redaction happens before any rendering.
Other proof fields keep their diagnostic values. Structural decoded grants, operations,
and attestations use `struct`. Their fields are unverified diagnostic data.
The `verification` field remains `:not_evaluated`.

Atom names and field keys MUST be plain identifiers matching `[a-z_][a-zA-Z0-9_]*[?!]?`.
The values `nil`, `true`, and `false` retain their own forms. Any value outside the grammar's
value domain renders as exactly `#unrenderable`: this includes maps, other structs, process
identifiers, references, functions, ports, non-byte-aligned bitstrings, improper lists (the
whole list), and atoms without a plain identifier name. Recognized structures missing a
required field also render as `#unrenderable`. Decoders never produce such values; only
implementations whose decoded values can be modified by hand need implement this form.
Rendering MUST be total for every value, and nonce redaction still precedes rendering.

A nonempty proper list whose every element is a two-element tuple with a plain-identifier
atom first element is a keyword list: render each pair as a field, without tuple braces or
the key's leading colon.
The empty list is `[]`. Other lists use ordinary list notation, including string-keyed
tagged JSON object-member pairs. A non-identifier atom key makes the entire list an ordinary
list; its pair renders as a tuple with `#unrenderable` for the atom element. Empty tuples
are `{}`.
There is no character-list inference. Tags such as `:integer` and `:float` stay distinct.

### Structural rendering

Start each structural diagnostic with a remaining container budget of **200**.
Traversal is left to right, depth first, sharing one remaining budget across all nesting
and subsequent siblings. Opening and closing delimiters cost nothing.

Before each struct field, keyword pair, ordinary list element, tuple element, or byte of a
nonprintable binary, check the remaining budget. If zero, emit `...` in place of the entire
remaining sequence and stop that sequence. Otherwise subtract one, then render that entry,
passing the remaining budget into its nested value. Continue with the budget returned by
that nested value. Struct fields and keyword pairs each cost one; their keys and the pair's
implicit two-tuple consume no additional units.

Scalar atoms, booleans, nil, integers, floats, quoted strings, and `#unrenderable` cost nothing
beyond the unit already charged by their enclosing sequence. A quoted string therefore still renders
at zero container budget. A nonempty nonprintable binary at zero renders `<<...>>`.
Empty containers render their empty delimiters even at zero. When the last entry uses the
last unit and no entries remain, do not append an ellipsis.

Ellipses are bare three ASCII periods, with the ordinary `, ` separator if an earlier entry
was emitted. Thus the forms include `[...]`, `{...}`, `<<...>>`, `%name{...}`,
`[value, ...]`, and `%name{key: value, ...}`.

Proofs retain their fixed form: every listed field is emitted, each visible value starts
its own budget of 200, and the field keys do not consume that budget. No proof field
sequence truncates. Fully redacted forms have neither budget nor visible values.

### Scalar rendering

Integers use base ten with a minus sign only when negative. For a finite binary64 float,
choose the fewest significant decimal digits that round trip to the same binary64 value
under round-to-nearest, ties-to-even. Among equally short candidates, choose the nearest
decimal value, breaking a remaining tie with an even final digit. Use those digits in fixed
or scientific notation, always retaining a decimal point and at least one fractional digit.
Scientific notation has one digit before that point, lowercase `e`, no plus sign, and no
leading zeroes in the exponent. For absolute values below 2^53, choose the notation with
fewer characters, preferring fixed notation on a tie. At or above 2^53, use scientific
notation. Preserve zero as `0.0` and negative zero as `-0.0`. For example: `100.0`, `1.0e3`,
`0.0001`, `1.2e-4`, `1.0e20`, `1.0e-7`. Floats are diagnostic values, not canonical JSON numbers.

To choose quoted-string versus binary notation, scan at most the first **4,096 Unicode
scalar values** of the binary. The printable set is U+0007–U+000D, U+001B, U+0020–U+007F,
U+00A0–U+D7FF, U+E000–U+FFFD, and U+10000–U+10FFFF. An invalid UTF-8 sequence or a scalar
outside that set encountered during the scan selects binary notation for the entire binary,
using its raw unsigned decimal bytes and the shared container budget. Otherwise use a
double-quoted string. The empty binary is `""`.

Quoted-string escaping has its own limit of **4,096 printable units** per string, independent
of the container budget. Each Unicode scalar costs one unit, except the consecutive
interpolation introducer U+0023 U+007B, which costs one unit for both characters and emits a
backslash followed by those two characters. Scan and escape in source order. Escaped output
length and UTF-8 byte length do not affect the unit count. If bytes remain after those units,
close the quote and append exactly ` <> ...`; otherwise append nothing.

The escapes for U+0007, U+0008, U+0009, U+000A, U+000B, U+000C, U+000D, U+001B, U+0022,
U+005C, and U+007F are respectively a backslash followed by
`a`, `b`, `t`, `n`, `v`, `f`, `r`, `e`, `"`, a backslash, and `d`.
The following printable scalars emit a backslash, lowercase `u`, and exactly four uppercase
hexadecimal digits:

- U+00A0, U+034F, U+061C, U+FEFF;
- U+2000–U+200F, U+2028–U+202E, U+205F–U+2064, U+2066–U+2069, U+FFF9–U+FFFC.

All other printable scalars emit their unchanged UTF-8 bytes.

Because an interpolation introducer consumes two scalars but one escaping unit, escaping
can reach beyond the printability scan's prefix. In that suffix, U+0000 emits `\0`;
other nonprintable scalars below U+0100 emit `\x` followed by two uppercase hexadecimal
digits, and U+FFFE and U+FFFF emit `\x{FFFE}` and `\x{FFFF}`. An invalid UTF-8 byte emits
`\x` followed by two uppercase hexadecimal digits and consumes one escaping unit.
These escapes keep the quoted form free of raw controls and invalid UTF-8.

### Fixtures and independent derivation

The canonical display fixtures are `test/fixtures/sdk_rendering/decoded-rendering.json`,
`decoded-wire-rendering.json`, and `decoded-binary-rendering.json`. Each SDK carries
byte-identical copies in its own fixture directory. Their existing expected strings remain
unchanged. Constructed scalar entries with keys prefixed by `float:` use the remainder of
the key as a decimal binary64 input and the entry value as its expected display bytes.
The fixtures cover all majors, nested tagged JSON, shared-budget truncation, public-key
binaries, printable strings, escaping, and redacted values.

Implementations derive their algorithms independently from this contract and these fixture
bytes. They do not derive an algorithm from another implementation's source, source-symbol
citations, or cross-language transliteration. Equality is an exact byte comparison; a
self-round-trip or a substring match cannot establish agreement.
