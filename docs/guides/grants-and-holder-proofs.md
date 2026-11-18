# Grants and holder proofs

A grant is an issuer-signed capability: it fixes a holder key thumbprint, issuer, audience set,
validity window, and named operations with argument selectors. A proof is a holder-signed
binding of that exact grant to one method, normalized target URI, invocation id, operation,
and type-preserving argument digest. A copied grant cannot supply the holder's signature.

The grant digest uses the exact compact bytes; decoding and re-encoding a grant changes its
identity. Every signature covers the standard JWS signing input, the two original base64url
segments joined with a period. Producers compute those bytes; your signer holds the private
key and returns a raw signature for assembly. Assembly validates structure and canonical
signature encoding; verification establishes cryptographic validity under supplied public keys.

Use `verify_grant/3` to inspect a grant under explicit trusted inputs. Use `check_envelope/2`
to verify an invocation, including holder binding and selectors. Neither reserves an invocation
or authorizes an effect. See [getting started](getting-started.md) for the complete first
integration and the [core notebook](../notebooks/bap-walkthrough.livemd) for success and refusal.
