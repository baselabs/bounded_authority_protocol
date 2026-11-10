# Troubleshooting `{:error, :invalid}`

Every verification failure returns the same value, `{:error, :invalid}`. A wrong key, a changed
byte, an expired grant, and an argument outside a selector all look identical, so the error
tells an attacker nothing. The cost is that it tells you nothing either. This page is the
checklist for finding the cause from your own inputs, in the order verification checks them.

The package has no diagnostic mode and never will: a second verdict path that names the failing
stage would leak exactly what the single error hides. Diagnose with the decoders, which read
claims without checking any signature, and compare them with what you passed. Use the decoded
values for diagnosis only, never for a decision.

## Set up a working envelope

The blocks on this page run, in order, in the repository's test suite. The first builds a
contract-major 1 envelope that verifies, so each later block can change one input.

```elixir
alias BoundedAuthorityProtocol.V1
alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedRequest, Grant, Operation, Proof, TrustedIssuer}

{issuer_public, issuer_private} = :crypto.generate_key(:eddsa, :ed25519)
{holder_public, holder_private} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, holder_thumbprint} = V1.Jwk.public_key_thumbprint_raw(holder_public, %{})

sign = fn input, private_key ->
  {:ok, compact} = V1.assemble_compact(input, :crypto.sign(:eddsa, :none, input.message, [private_key, :ed25519]))
  compact
end

grant = %Grant{
  key_id: "issuer-1",
  issuer: "https://issuer.example",
  grant_id: "grant-backup-001",
  audiences: ["https://storage.example"],
  issued_at: 1_800_000_000,
  not_before: 1_800_000_000,
  expires_at: 1_800_003_600,
  holder_thumbprint: holder_thumbprint,
  operations: [%Operation{name: "snapshot_volume", selectors: [{:equals, ["volume"], {:string, "vol-7"}}]}]
}

{:ok, grant_input} = V1.grant_signing_input(grant, %{})
grant_compact = sign.(grant_input, issuer_private)

arguments = {:object, [{"retain_days", {:integer, 30}}, {"volume", {:string, "vol-7"}}]}

proof = %Proof{
  holder_public_key: holder_public,
  proof_id: "proof-backup-001",
  method: "POST",
  target_uri: "https://storage.example/snapshots",
  issued_at: 1_800_000_100,
  nonce: nil,
  invocation_id: "4a8e2c6f-1d3b-4f7a-9e5c-0b2d4f6a8c1e",
  operation: "snapshot_volume",
  grant_compact: grant_compact,
  cast_arguments: arguments
}

{:ok, proof_input} = V1.proof_signing_input(proof, %{})
credentials = %Credentials{grant: grant_compact, proof: sign.(proof_input, holder_private)}

expected = %ExpectedRequest{
  trusted_issuer: %TrustedIssuer{key_id: "issuer-1", public_key: issuer_public},
  issuer: "https://issuer.example",
  audience: "https://storage.example",
  method: "POST",
  target_uri: "https://storage.example/snapshots",
  invocation_id: "4a8e2c6f-1d3b-4f7a-9e5c-0b2d4f6a8c1e",
  operation: "snapshot_volume",
  cast_arguments: arguments,
  evaluation_time: 1_800_000_130,
  clock_skew: 60,
  proof_max_age: 300,
  nonce: :not_required,
  bounds: %{}
}

elem(V1.check_envelope(credentials, expected), 0)
```

The value is `:ok`.

## A comparison helper

`decode_grant/2` and `decode_proof/2` return the claims the credentials carry, unverified.
`request_digest/3` computes the argument digest the proof must carry. The helper below compares
them with an `ExpectedRequest` and names the fields that differ. It is a debugging aid for your
own credentials; keep it out of the request path and never log its output in production, because
it reads values the redacted facts deliberately omit.

```elixir
diagnose = fn %Credentials{grant: grant, proof: proof}, %ExpectedRequest{} = expected ->
  with {:ok, decoded_grant} <- V1.decode_grant(grant, %{}),
       {:ok, decoded_proof} <- V1.decode_proof(proof, %{}),
       {:ok, digest} <- V1.request_digest(expected.operation, expected.cast_arguments, %{}),
       {:ok, normalized_uri} <- V1.Uri.normalize(expected.target_uri, %{}) do
    window = expected.evaluation_time - expected.proof_max_age - expected.clock_skew

    checks = [
      key_id: decoded_grant.key_id == expected.trusted_issuer.key_id,
      issuer: decoded_grant.issuer == expected.issuer,
      audience: expected.audience in decoded_grant.audiences,
      grant_window:
        decoded_grant.not_before - expected.clock_skew <= expected.evaluation_time and
          expected.evaluation_time < decoded_grant.expires_at + expected.clock_skew,
      method: decoded_proof.method == expected.method,
      target_uri: decoded_proof.target_uri == expected.target_uri and normalized_uri == expected.target_uri,
      invocation_id: decoded_proof.invocation_id == expected.invocation_id,
      operation: decoded_proof.operation == expected.operation,
      cast_arguments: Base.url_encode64(decoded_proof.request_hash, padding: false) == digest,
      proof_age:
        window <= decoded_proof.issued_at and decoded_proof.issued_at <= expected.evaluation_time + expected.clock_skew,
      nonce: (decoded_proof.nonce == nil) == (expected.nonce == :not_required)
    ]

    for {field, false} <- checks, do: field
  else
    _undecodable -> [:undecodable_input]
  end
end

diagnose.(credentials, expected)
```

The value is `[]`: nothing differs. The helper does not check signatures, the holder key binding,
selectors, or bounds; the checklist below covers those.

Three common mistakes, each found by the helper:

```elixir
[
  diagnose.(credentials, %{expected | method: "post"}),
  diagnose.(credentials, %{expected | evaluation_time: 1_800_000_130_000}),
  diagnose.(credentials, %{expected | target_uri: "https://STORAGE.example:443/snapshots"})
]
```

The value is `[[:method], [:grant_window, :proof_age], [:target_uri]]`: a lowercase method, an
evaluation time in milliseconds, and a target URI that is not in normalized form. Each of them
makes `check_envelope/2` return `{:error, :invalid}`.

## The checklist

Work down the list; the first difference you find is usually the cause.

### 1. Input shapes

- **Structs and tags.** Pass the package's structs, and pass arguments in the tagged JSON form:
  `{:object, [{"volume", {:string, "vol-7"}}]}`, not `%{"volume" => "vol-7"}`. An untagged map
  is invalid input.
- **Times are Unix seconds.** `evaluation_time`, `issued_at`, `not_before`, and `expires_at` are
  integers in seconds. `System.os_time(:second)`, not `System.os_time()` or milliseconds.
- **Skew and age limits.** `clock_skew` is at most 60 and `proof_max_age` at most 300; a larger
  value is invalid, not clamped.
- **Bounds.** `bounds` is `%{}` (the profile maxima), a `Bounds` struct, or a map of known
  `Bounds` field names with smaller positive integers. An unknown key such as `max_depth`, a zero,
  or a value above the maximum is invalid. A tightened bound that the credential exceeds
  rejects the credential.

### 2. Profile and contract-major

- Call the namespace that matches the bytes: `V1`, `V2`, or `V3` for contract-majors 1, 2, and 3,
  or a sibling profile's own namespace. Each rejects every other profile's bytes, and the grant
  and the proof must come from the same contract-major. [Choosing a profile](choosing-a-profile.md)
  shows how to tell them apart.
- A local-loopback proof (`typ: "ba+loopback-proof"`) verifies only through
  `BoundedAuthorityProtocol.ApplicationProfile.LocalLoopbackHttp.V1`.

### 3. Trust

- **Key id.** `trusted_issuer.key_id` must equal the grant's `kid` exactly (case-sensitive).
- **Key bytes.** The public key must be the issuer's raw key: 32 bytes for Ed25519, the 65-byte
  uncompressed point `0x04 || x || y` for ES256. A key that fails
  `BoundedAuthorityProtocol.Ed25519.acceptable_public_key?/1` or
  `BoundedAuthorityProtocol.Es256.acceptable_public_key?/1` never verifies.
- **Signature.** A grant signed by another key, or bytes changed after signing, fail here.

### 4. Grant claims

- **Issuer** equals `expected.issuer` byte for byte.
- **Audience.** `expected.audience` is one of the grant's audiences, exactly: a trailing slash or
  a different scheme is a different audience.
- **Window.** The evaluation time lies within `not_before` and `expires_at`, allowing
  `clock_skew`.

### 5. Proof binding

- **Holder.** The proof is signed by the key whose RFC 7638 thumbprint the grant names
  (`V1.Jwk.public_key_thumbprint_raw/2`; `V3.EcJwk.public_key_thumbprint_raw/2` for ES256).
- **Grant.** The proof's `grant_compact` is the exact grant compact you pass in `Credentials`.
- **Method** matches the proof byte for byte. Methods are case-sensitive and never normalized,
  so pass the token your server received, conventionally uppercase: `"POST"` and `"post"` differ.
- **Target URI** is the normalized absolute URI: lowercase scheme and host, no default port.
  `V1.Uri.normalize/2` returns the normalized form; derive it from your own configured origin and
  the request path, never from the `Host` header.
- **Invocation id and operation** match exactly. The operation is the one your route maps to,
  not one the client names.
- **Arguments.** The proof binds a digest of the operation and the tagged arguments. A different
  tag (`{:float, 30.0}` against `{:integer, 30}`), a different member, or a different value gives
  a different digest. Compare `request_digest/3` over your arguments with the proof's
  `request_hash`, as the helper does.
- **Age.** The proof's `issued_at` lies between
  `evaluation_time - proof_max_age - clock_skew` and `evaluation_time + clock_skew`.
- **Nonce.** With `:not_required` the proof must carry no nonce; with `{:required, nonce}` it must
  carry exactly that nonce.

### 6. Selectors

- Every selector of the operation must hold for the arguments. `equals` and `one_of` compare
  tagged values exactly, so `{:integer, 7}` never equals `{:float, 7.0}`.
- Range bounds (`lte`, `gte`, contract-majors 2 and 3) compare integers with integers and floats
  with floats only.
- A grant whose `equals` value or `one_of` member holds a float zero does not decode on any
  contract-major, and a grant producer refuses a float-tagged whole-number selector value
  ([erratum 6](../errata.md)).

### 7. Producer refusals

The producer functions return `{:error, :invalid}` too, before anything is signed:

- `assemble_compact/2,3` refuses a signature of the wrong width or one no conforming signer emits
  (ES256 high-S or out of range; Ed25519 `S >= L`, or a non-canonical or small-order `R`). For
  ES256, convert a DER signature with `Es256.der_to_raw/1` and normalize it with
  `Es256.normalize_low_s/1` first ([Recipes](recipes.md#es256-from-a-kms-or-hsm)).
- `grant_signing_input/2` and `proof_signing_input/2` refuse a key that fails key acceptance, a
  struct field of the wrong type or over a bound, and a float-tagged whole-number selector value.

If every item matches and verification still fails, run the packaged conformance corpora
([Recipes](recipes.md#run-every-packaged-corpus)): a corpus that does not agree points at the
installation, not at your inputs.
