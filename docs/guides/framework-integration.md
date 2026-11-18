# Integrate with a host

The integration boundary is the class of request-processing hosts: web servers, workers,
command handlers, RPC services, and batch processors. Plug and Phoenix are examples of that
class. No framework dependency or host policy enters the verifier package.

## Request boundary

1. Select the profile from authenticated route or client configuration before parsing credentials.
2. Enforce transport and body limits. Accept one raw grant and one raw proof; reject duplicate
   credential headers and ambiguous encodings. Never accept caller-provided facts.
3. Build the external target from configured, authenticated origin information and the actual
   request path. At a trusted proxy boundary validate that boundary's forwarding policy first;
   never trust arbitrary `Host`, `Forwarded`, or `X-Forwarded-*` values.
4. Map the route to the operation and cast arguments through the host's own schema. Preserve
   integer and float tags. Derive method and invocation identity from the accepted request.
5. Select one already-trusted issuer public key, expected audience, time policy, nonce policy,
   and tightened bounds. Call the chosen profile's `check_envelope/2` with raw credentials.
6. On `{:error, :invalid}`, send the same host refusal for every invalid credential. Do not
   fall back to another profile or reveal diagnostic comparisons to the requester.
7. On success, check revocation, reserve the issuer/grant/invocation execution identity atomically,
   and apply host authorization policy before executing the effect.

The [Plug/Phoenix recipe](recipes.md#plug-and-phoenix-integration) contains the
executable middleware example. A worker derives the same expected context from its authenticated
message contract; an RPC service derives it from its authenticated route and typed arguments.
The host owns error translation, lifecycle, store availability, and all transaction boundaries.

## Local listeners and evidence import

A direct local-development listener can explicitly select the literal-loopback HTTP profile.
That profile requires a server nonce and neither supplies TLS nor isolates local processes.
Evidence import selects explicit historical keys and expected chain/object boundaries; import
success cannot authorize a live invocation. See [evidence](evidence.md).
