//! The orchestration engine: identify → dispatch → score → recursively unwrap.
//!
//! RED-phase stub — returns nothing. The GREEN commit implements the detectors.

use crate::{Candidate, Limits};

/// Identify a blob with default [`Limits`]. Returns scored candidates, best
/// (highest [`Confidence`](crate::Confidence)) first.
#[must_use]
pub fn identify(bytes: &[u8]) -> Vec<Candidate> {
    identify_with_limits(bytes, Limits::default(), 0)
}

/// Identify a blob with explicit resource [`Limits`] and a starting recursion
/// `depth` — the entry point the recursive unwrap calls into.
#[must_use]
pub fn identify_with_limits(_bytes: &[u8], _limits: Limits, _depth: usize) -> Vec<Candidate> {
    Vec::new()
}
