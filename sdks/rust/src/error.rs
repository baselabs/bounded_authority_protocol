//! The single closed error shape.
//!
//! The protocol mandates exactly one error (`REQ1-VERIFY-return-shape`): every
//! unknown version, algorithm, header, claim, selector, holder mode, duplicate
//! key, invalid encoding, or over-limit input collapses to [`Invalid`] —
//! value-free, fail-closed. There are no variants, no `thiserror`/`anyhow`, and
//! no `From` conversion ladder (there is exactly one error). The `?` operator
//! works against any function returning [`Result<_>`](Result) directly.

/// The sole error returned by every verification function.
///
/// A unit struct — it carries no diagnostic information by design: the protocol
/// forbids value leakage on the error path. Derives only [`Debug`], [`Clone`],
/// [`Copy`], [`PartialEq`], [`Eq`]; no `Serialize` or `Display`, so it cannot
/// be accidentally threaded into a credential-shaped value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;

/// The canonical result alias for every public function in the crate.
///
/// Every façade and versioned primitive returns `Result<T>` = `std::result::Result<T, Invalid>`.
pub type Result<T> = std::result::Result<T, Invalid>;
