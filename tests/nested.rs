//! Recursive unwrapping: a base64 → gzip → JSON blob must report the whole chain.

mod common;

use blob_decoder::{identify, BlobKind};

#[test]
fn base64_of_gzip_of_json_reports_full_chain() {
    let Some(gz) = common::gzip(b"{\"nested\":true}") else {
        eprintln!("SKIP: gzip unavailable");
        return;
    };
    let Some(b64) = common::base64(&gz) else {
        eprintln!("SKIP: base64 unavailable");
        return;
    };
    let cands = identify(&b64);

    // Top reading: base64 wrapper.
    let top = &cands[0];
    assert_eq!(top.kind, BlobKind::Base64);

    // → gzip
    let gzip_chain = top.inner.as_ref().expect("base64 payload identified");
    assert_eq!(gzip_chain.best.kind, BlobKind::Gzip);

    // → json
    let json_chain = gzip_chain
        .best
        .inner
        .as_ref()
        .expect("gzip payload identified");
    assert_eq!(json_chain.best.kind, BlobKind::Json);
}
