// Package verifier is a typed Go verifier for the Bounded Authority Protocol
// frozen v1 profile (suite BAP1-Ed25519-SHA256).
//
// It reimplements the profile from the published spec (docs/protocol-v1.md),
// the governing ADRs, and the published conformance corpus alone — with no
// code-level derivation from the Elixir reference or the sibling SDKs
// (ADR 0014 D5).
//
// Verification is not authority: a successful result proves only that
// caller-supplied bytes satisfy caller-supplied trusted inputs and expected
// context. This library performs no I/O, trust discovery, key custody,
// signing, replay reservation, revocation checks, or business authorization.
//
// Every public function returns (T, error) where the error is either nil or
// exactly ErrInvalid — the Go spelling of the protocol's closed
// {:ok, value} | {:error, :invalid} result contract. No other error value is
// ever returned, and no failure carries input values.
package verifier

import "errors"

// ErrInvalid is the single, value-free failure result every public entry
// returns. It is a sentinel, never wrapped: callers compare with == (or
// errors.Is, which is equivalent here).
var ErrInvalid = errors.New("invalid")
