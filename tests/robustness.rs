//! Adversarial inputs: truncated streams, a decompression bomb, invalid base64,
//! and random bytes must degrade gracefully (never panic, never OOM).

mod common;

use blob_decoder::{identify, identify_with_limits, BlobKind, Confidence, Limits};

#[test]
fn truncated_gzip_does_not_panic_and_is_not_high() {
    let Some(full) = common::gzip(b"this is some content that will be cut in half midstream")
    else {
        eprintln!("SKIP: gzip unavailable");
        return;
    };
    let truncated = &full[..full.len() / 2];
    let cands = identify(truncated);
    // gzip magic is still present, so a Gzip reading is offered — but decode
    // failed, so it must NOT be High, and the payload chain is absent.
    let gz = cands.iter().find(|c| c.kind == BlobKind::Gzip);
    if let Some(gz) = gz {
        assert!(gz.score < Confidence::High);
        assert!(gz.inner.is_none());
        assert!(
            gz.summary.to_lowercase().contains("fail")
                || gz.summary.to_lowercase().contains("error"),
            "a failed decode must say so: {}",
            gz.summary
        );
    }
}

#[test]
fn zlib_bomb_is_capped_not_oom() {
    // 64 MiB of zeros compresses to a few KiB; with a 1 MiB output cap the
    // decoder must stop at the cap, flag it, and never allocate the full bomb.
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&vec![0u8; 64 * 1024 * 1024]).unwrap();
    let bomb = enc.finish().unwrap();

    let limits = Limits {
        max_depth: 4,
        max_output: 1024 * 1024,
        max_input: 128 * 1024 * 1024,
    };
    let cands = identify_with_limits(&bomb, limits, 0);
    let zlib = cands
        .iter()
        .find(|c| c.kind == BlobKind::Zlib)
        .expect("zlib reading present");
    let inner = zlib.inner.as_ref().expect("payload present (capped)");
    assert!(inner.capped, "the bomb must be reported as capped");
    assert!(
        inner.decoded_len <= limits.max_output,
        "decoded output must not exceed the cap"
    );
}

#[test]
fn invalid_base64_does_not_claim_base64() {
    // Contains characters outside the base64 alphabet.
    let cands = identify(b"not!!valid!!base64!!@@##");
    assert!(
        cands.iter().all(|c| c.kind != BlobKind::Base64),
        "junk with non-alphabet chars must not be read as base64"
    );
}

#[test]
fn random_bytes_degrade_gracefully() {
    let junk: Vec<u8> = (0u16..500)
        .map(|i| (i.wrapping_mul(37) ^ 0xA5) as u8)
        .collect();
    let cands = identify(&junk);
    assert!(!cands.is_empty());
    assert!(cands.iter().all(|c| c.score < Confidence::High));
}

#[test]
fn deeply_nested_wrappers_terminate() {
    // base64 of base64 of base64 … must stop at the depth cap without looping.
    let mut data = b"{\"x\":1}".to_vec();
    for _ in 0..20 {
        let Some(b) = common::base64(&data) else {
            eprintln!("SKIP: base64 unavailable");
            return;
        };
        // strip the trailing newline base64(1) adds so the next layer is clean
        data = b.iter().copied().filter(|c| *c != b'\n').collect();
    }
    let cands = identify(&data);
    assert!(!cands.is_empty(), "must terminate and return candidates");
}
