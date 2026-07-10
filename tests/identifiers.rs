//! UUID (string + raw bytes) and hex identification, incl. the honest scoring
//! gap: a canonical UUID *string* is High; 16 arbitrary *bytes* are only Low.

mod common;

use blob_decoder::{identify, BlobKind, Confidence};

#[test]
fn canonical_uuid_string_is_high_confidence() {
    let Some(out) = common::run("uuidgen", &[]) else {
        eprintln!("SKIP: uuidgen unavailable");
        return;
    };
    let s = String::from_utf8_lossy(&out);
    let uuid = s.trim();
    let cands = identify(uuid.as_bytes());
    let top = &cands[0];
    assert_eq!(top.kind, BlobKind::Uuid);
    assert_eq!(top.score, Confidence::High);
    assert!(
        top.summary.contains(uuid) || top.summary.to_lowercase().contains(&uuid.to_lowercase())
    );
}

#[test]
fn raw_16_bytes_are_only_a_low_confidence_uuid() {
    // Any 16 bytes form a syntactically valid UUID, so this must NOT be High —
    // over-claiming here would fabricate certainty.
    let sixteen = [
        0x55u8, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00,
        0x00,
    ];
    let cands = identify(&sixteen);
    let uuid = cands
        .iter()
        .find(|c| c.kind == BlobKind::Uuid)
        .expect("a UUID reading is offered for 16 bytes");
    assert_eq!(uuid.score, Confidence::Low);
}

#[test]
fn hex_text_wrapping_json_is_recovered() {
    let payload = b"{\"x\":1}";
    let hexed = hex::encode(payload);
    let cands = identify(hexed.as_bytes());
    let hex_cand = cands
        .iter()
        .find(|c| c.kind == BlobKind::Hex)
        .expect("hex reading present");
    let inner = hex_cand.inner.as_ref().expect("hex payload identified");
    assert_eq!(inner.best.kind, BlobKind::Json);
    // A hex wrapper whose payload is a concrete type is Medium (better than a
    // bare hex-charset coincidence).
    assert_eq!(hex_cand.score, Confidence::Medium);
}
