#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Core API contract: confidence ordering, best-first sorting, the always-present
//! Unknown fallback, honest scoring on junk, and lossless serialization.

use blob_decoder::{identify, BlobKind, Confidence};

#[test]
fn confidence_orders_high_above_medium_above_low() {
    assert!(Confidence::High > Confidence::Medium);
    assert!(Confidence::Medium > Confidence::Low);
}

#[test]
fn empty_input_yields_unknown() {
    let cands = identify(b"");
    assert!(
        !cands.is_empty(),
        "must always return at least one candidate"
    );
    assert_eq!(cands[0].kind, BlobKind::Unknown);
}

#[test]
fn unknown_summary_shows_the_raw_head_bytes() {
    // Robustness: an "unknown" finding must surface the actual bytes, in hex.
    let junk = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let cands = identify(&junk);
    let unknown = cands
        .iter()
        .find(|c| c.kind == BlobKind::Unknown)
        .expect("unknown candidate present");
    assert!(
        unknown.summary.to_lowercase().contains("dead"),
        "unknown summary should include the head bytes in hex, got: {}",
        unknown.summary
    );
}

#[test]
fn random_bytes_never_claim_high_confidence() {
    // 21 arbitrary bytes: not a UUID (not 16), not valid magic — must degrade to
    // Low/Unknown, never a confident verdict.
    let junk = [
        0x37u8, 0x9a, 0x02, 0xf1, 0x13, 0x88, 0xcc, 0x01, 0x77, 0x42, 0x9e, 0xde, 0x05, 0xba, 0xad,
        0xf3, 0x0d, 0x11, 0x22, 0x33, 0x44,
    ];
    let cands = identify(&junk);
    assert!(
        cands.iter().all(|c| c.score < Confidence::High),
        "random bytes must not produce a High-confidence reading"
    );
}

#[test]
fn candidates_are_sorted_best_first() {
    let gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let cands = identify(gz);
    for w in cands.windows(2) {
        assert!(w[0].score >= w[1].score, "candidates must be sorted desc");
    }
}

#[test]
fn output_serializes_to_json() {
    let cands = identify(b"{\"a\":1}");
    let json = serde_json::to_string(&cands).expect("candidates serialize");
    assert!(json.contains("json"));
}
