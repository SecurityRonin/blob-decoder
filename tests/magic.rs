//! Magic-signature identification against REAL inputs produced by independent
//! tools (python3 plistlib/zlib, system gzip, the snap crate). Each is env-gated:
//! a missing producer SKIPs, never fails.

mod common;

use blob_decoder::{identify, BlobKind, Confidence};

#[test]
fn binary_plist_is_identified() {
    let Some(bytes) = common::bplist_dict() else {
        eprintln!("SKIP: python3 plistlib unavailable");
        return;
    };
    let cands = identify(&bytes);
    assert_eq!(cands[0].kind, BlobKind::BinaryPlist);
    assert_eq!(cands[0].score, Confidence::High);
    assert!(
        cands[0].summary.to_lowercase().contains("dict"),
        "summary should describe the root dict, got: {}",
        cands[0].summary
    );
}

#[test]
fn xml_plist_is_identified() {
    let Some(bytes) = common::xml_plist_dict() else {
        eprintln!("SKIP: python3 plistlib unavailable");
        return;
    };
    let cands = identify(&bytes);
    assert_eq!(cands[0].kind, BlobKind::XmlPlist);
    assert_eq!(cands[0].score, Confidence::High);
}

#[test]
fn gzip_wrapping_json_is_recovered() {
    let Some(bytes) = common::gzip(b"{\"x\":1}") else {
        eprintln!("SKIP: gzip unavailable");
        return;
    };
    let cands = identify(&bytes);
    assert_eq!(cands[0].kind, BlobKind::Gzip);
    assert_eq!(cands[0].score, Confidence::High);
    let inner = cands[0].inner.as_ref().expect("gzip payload identified");
    assert_eq!(inner.best.kind, BlobKind::Json);
}

#[test]
fn zlib_wrapping_json_is_recovered() {
    let Some(bytes) = common::zlib_compress(b"{\"x\":1}") else {
        eprintln!("SKIP: python3 zlib unavailable");
        return;
    };
    let cands = identify(&bytes);
    assert_eq!(cands[0].kind, BlobKind::Zlib);
    assert_eq!(cands[0].score, Confidence::High);
    let inner = cands[0].inner.as_ref().expect("zlib payload identified");
    assert_eq!(inner.best.kind, BlobKind::Json);
}

#[test]
fn snappy_framed_is_identified() {
    use std::io::Write;
    let mut enc = snap::write::FrameEncoder::new(Vec::new());
    enc.write_all(b"{\"x\":1}").unwrap();
    let bytes = enc.into_inner().unwrap();
    let cands = identify(&bytes);
    assert_eq!(cands[0].kind, BlobKind::Snappy);
    assert_eq!(cands[0].score, Confidence::High);
}

#[test]
fn json_object_is_identified() {
    let cands = identify(b"{\"a\":[1,2,3],\"b\":true}");
    assert_eq!(cands[0].kind, BlobKind::Json);
    assert_eq!(cands[0].score, Confidence::High);
}

#[test]
fn json_array_is_identified() {
    let cands = identify(b"[1, 2, 3]");
    assert_eq!(cands[0].kind, BlobKind::Json);
    assert_eq!(cands[0].score, Confidence::High);
}
