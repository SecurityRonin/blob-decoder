#![no_main]
//! Invariant: no input may panic the V8 / Blink structured-clone deserializer,
//! and the depth + node caps must keep memory and stack bounded. Both the raw V8
//! and the Blink-enveloped entry points are exercised on the same bytes; the
//! first byte selects which the fuzzer emphasises so it explores both framings.
use blob_decoder::v8_value::{deserialize_blink_with_limits, deserialize_with_limits, V8Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Modest caps so the fuzzer explores structure (nesting, lengths, references)
    // rather than one giant allocation.
    let limits = V8Limits {
        max_depth: 64,
        max_nodes: 1 << 16,
    };
    let _ = deserialize_with_limits(data, limits);
    let _ = deserialize_blink_with_limits(data, limits);
});
