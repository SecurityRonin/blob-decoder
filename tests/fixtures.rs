#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Identification against committed, real plist fixtures (produced by python3
//! `plistlib`; see tests/data/README.md). Unlike the tool-gated tests these run
//! everywhere, so the plist decode paths are always exercised.

use blob_decoder::{identify, BlobKind, Confidence};

const BPLIST: &[u8] = include_bytes!("data/sample.bplist");
const XMLPLIST: &[u8] = include_bytes!("data/sample.plist");

#[test]
fn committed_binary_plist_is_identified() {
    let cands = identify(BPLIST);
    assert_eq!(cands[0].kind, BlobKind::BinaryPlist);
    assert_eq!(cands[0].score, Confidence::High);
    assert!(cands[0].summary.contains("dict"), "{}", cands[0].summary);
}

#[test]
fn committed_xml_plist_is_identified() {
    let cands = identify(XMLPLIST);
    assert_eq!(cands[0].kind, BlobKind::XmlPlist);
    assert_eq!(cands[0].score, Confidence::High);
}

#[test]
fn bplist_magic_with_garbage_body_is_medium_not_high() {
    // Magic present, structure invalid → reported, but downgraded and payloadless.
    let mut junk = b"bplist00".to_vec();
    junk.extend_from_slice(&[0xff, 0x00, 0x13, 0x37, 0xab]);
    let cands = identify(&junk);
    let bp = cands
        .iter()
        .find(|c| c.kind == BlobKind::BinaryPlist)
        .expect("bplist reading present");
    assert!(bp.score < Confidence::High);
    assert!(bp.summary.to_lowercase().contains("fail"), "{}", bp.summary);
}

#[test]
fn snappy_magic_with_garbage_body_does_not_panic() {
    let mut junk = vec![0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    junk.extend_from_slice(&[0xde, 0xad, 0xff, 0x00, 0x99]);
    let cands = identify(&junk);
    // A reading is produced (Snappy or Unknown); the point is: no panic.
    assert!(!cands.is_empty());
}
