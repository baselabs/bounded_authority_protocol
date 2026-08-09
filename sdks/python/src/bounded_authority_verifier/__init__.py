"""``bounded_authority_verifier`` — provider-neutral, deterministic verifier SDK for bounded
proof-of-possession authority (the BAP v1 verification profile, reimplemented in Python).

The public surface re-exports the 17-function façade + the versioned primitives the public contract
names (protocol-v1.md § Public verification contract, L266-309).

No ``authorized`` / ``decision`` surface (AGENTS rule 1); every function returns ``Result[T] =
Ok | Err``, mirroring ``{:ok, value} | {:error, :invalid}``. Facts are value-bearing, redacted, and
non-authorizing.
"""

from __future__ import annotations

from .base64url import base64url_decode, base64url_encode
from .bounds import MAXIMA, MAXIMUM_BOUNDS, Bounds, bounds_maximum, bounds_new
from .compact import SigningInput, assemble_compact
from .digest import REQUEST_PREFIX, typed_project
from .ed25519 import sha256
from .error import Err, InvalidError, Ok, Result, err, fail, ok, require
from .facts import (
    AnchoredExportFacts,
    AnchorFacts,
    ChainFacts,
    EnvelopeFacts,
    GrantDecoded,
    GrantFacts,
    KeyLocator,
    KeyTransitionFacts,
    ProofDecoded,
)
from .jcs import jcs_encode
from .json_alg import (
    JArray,
    JBool,
    JFloat,
    JInt,
    JNull,
    JObject,
    JString,
    Tagged,
    json_decode,
    str_utf8,
    utf8_str,
)
from .jwk import (
    OkpPublic,
    jwk_decode_public,
    jwk_encode_public,
    jwk_from_public_key,
    public_key_thumbprint_raw,
    thumbprint,
    thumbprint_preimage,
    thumbprint_raw,
)
from .selector import Selector, parse_selector, selector_matches, semantic_identity
from .uri import uri_normalize
from .v1 import (
    ALG,
    ANCHOR_TYP,
    ARCHIVE_PREFIX,
    GRANT_TYP,
    PROOF_TYP,
    ROW_PREFIX,
    AnchoredExportInput,
    ArchivedObject,
    BoundaryAnchorProducer,
    ChainInput,
    ConsumptionEntry,
    EncodedAnchoredExport,
    EncodedConsumptionEntry,
    ExpectedAnchor,
    ExpectedChain,
    ExpectedExport,
    ExpectedGrant,
    ExpectedKeyTransition,
    ExpectedRequest,
    GrantProducer,
    HistoricalKeyChain,
    HistoricalPublicKey,
    KeyTransitionProducer,
    NonceNotRequired,
    NonceRequired,
    OperationInput,
    ProofProducer,
    TrustedIssuer,
    boundary_anchor_signing_input,
    check_chain,
    check_envelope,
    decode_grant,
    decode_proof,
    encode_anchored_export,
    encode_consumption_entry,
    grant_signing_input,
    key_transition_signing_input,
    proof_signing_input,
    request_digest,
    untrusted_key_locator,
    verify_anchored_export,
    verify_grant,
    verify_historical_anchor,
    verify_key_transition,
)

__all__ = [
    # 17 façade functions
    "untrusted_key_locator",
    "decode_grant",
    "decode_proof",
    "verify_grant",
    "check_envelope",
    "request_digest",
    "encode_consumption_entry",
    "check_chain",
    "grant_signing_input",
    "proof_signing_input",
    "assemble_compact",
    "boundary_anchor_signing_input",
    "key_transition_signing_input",
    "encode_anchored_export",
    "verify_historical_anchor",
    "verify_key_transition",
    "verify_anchored_export",
    # dispatch structs
    "TrustedIssuer", "ExpectedGrant", "HistoricalPublicKey", "ExpectedAnchor",
    "ExpectedKeyTransition", "ConsumptionEntry", "ChainInput", "ExpectedChain",
    "ExpectedRequest", "NonceNotRequired", "NonceRequired", "OperationInput",
    "GrantProducer", "ProofProducer", "BoundaryAnchorProducer", "KeyTransitionProducer",
    "AnchoredExportInput", "ExpectedExport", "ArchivedObject", "HistoricalKeyChain",
    "EncodedConsumptionEntry", "EncodedAnchoredExport", "SigningInput", "Selector",
    # primitives
    "jwk_encode_public", "jwk_decode_public", "thumbprint", "thumbprint_raw",
    "thumbprint_preimage", "public_key_thumbprint_raw", "jwk_from_public_key",
    "OkpPublic", "uri_normalize",
    "bounds_new", "bounds_maximum", "MAXIMUM_BOUNDS", "MAXIMA", "Bounds", "jcs_encode",
    "base64url_decode", "base64url_encode", "parse_selector", "selector_matches",
    "semantic_identity", "typed_project", "REQUEST_PREFIX", "ROW_PREFIX", "ARCHIVE_PREFIX",
    "sha256", "json_decode", "str_utf8", "utf8_str",
    "ALG", "GRANT_TYP", "PROOF_TYP", "ANCHOR_TYP",
    # error + result
    "InvalidError", "Ok", "Err", "Result", "ok", "err", "fail", "require",
    # tagged algebra types
    "Tagged", "JNull", "JBool", "JInt", "JFloat", "JString", "JArray", "JObject",
    # facts
    "GrantFacts", "EnvelopeFacts", "ChainFacts", "AnchorFacts",
    "KeyTransitionFacts", "AnchoredExportFacts", "GrantDecoded", "ProofDecoded", "KeyLocator",
]

__version__ = "0.1.0"
