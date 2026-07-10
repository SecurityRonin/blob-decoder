#![no_main]
//! Invariant: no input may panic `identify`, and the recursion + decompression
//! caps must keep memory bounded. Runs with modest [`Limits`] so the fuzzer
//! explores blob *structure* (nested wrappers, malformed magic) rather than one
//! giant allocation.
use blob_decoder::{identify_with_limits, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_depth: 6,
        max_output: 1 << 20,
        max_input: 1 << 20,
    };
    let cands = identify_with_limits(data, limits, 0);
    for c in &cands {
        let _ = c.score;
        let _ = c.summary.len();
        // Walk the full decoded chain, touching every link.
        let mut cur = c.inner.as_deref();
        while let Some(chain) = cur {
            let _ = chain.decoded_len;
            let _ = chain.capped;
            cur = chain.best.inner.as_deref();
        }
    }
});
