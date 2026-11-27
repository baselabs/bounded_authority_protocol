// Package verifier implements deterministic Bounded Authority Protocol verification.
//
// Derived from the spec and certified corpus, not from any sibling-SDK or
// reference source (docs/design/conformance-contract.md, Independent implementation rule).
//
// Verification is not authority: a successful result proves only that
// caller-supplied bytes satisfy caller-supplied trusted inputs and expected
// context. This library performs no I/O, trust discovery, key custody,
// signing, replay reservation, revocation checks, or business authorization.
//
// Error-returning APIs use ErrInvalid for failures. The action approval verifier
// returns value-free diagnostics for host-local use.
package verifier

import "errors"

// ErrInvalid is the closed, value-free failure sentinel.
// Callers compare with == (or
// errors.Is, which is equivalent here).
var ErrInvalid = errors.New("invalid")
