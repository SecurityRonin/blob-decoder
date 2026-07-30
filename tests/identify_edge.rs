#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Engine edge paths: the resource-limit short-circuit, the "magic matched but the
//! payload failed to decode" Medium leaves, the UTF-16LE heuristic, and the plist
//! root-type descriptions.
//!
//! Provenance of the plist fixtures built here: each is produced **in-test** by the
//! `plist` crate (the reference implementation this engine delegates to) or is a
//! hand-written XML plist per Apple's `man 5 plist` DTD — so the expected root type
//! is the constructed one, not an assumption about a downloaded file.

use blob_decoder::{identify, identify_with_limits, BlobKind, Confidence, Limits};

fn candidate_of(bytes: &[u8], kind: BlobKind) -> blob_decoder::Candidate {
    identify(bytes)
        .into_iter()
        .find(|c| c.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} candidate for {bytes:?}"))
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

/// An input above `max_input` skips the *heuristic* detectors (they scan or decode
/// the whole blob) while magic-signature detection still runs. The base64 text below
/// would normally be claimed as Base64; over the cap it is not offered at all.
#[test]
fn oversized_input_skips_the_heuristic_detectors() {
    let b64 = b"aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=";
    let limits = Limits {
        max_input: 4,
        ..Limits::default()
    };
    let capped = identify_with_limits(b64, limits, 0);
    assert!(
        !capped.iter().any(|c| c.kind == BlobKind::Base64),
        "heuristic detectors must not run above max_input: {capped:?}"
    );
    assert_eq!(capped[0].kind, BlobKind::Unknown);

    // Same bytes under the default limits ARE claimed as base64 — proving the
    // difference is the cap, not the input.
    assert!(identify(b64).iter().any(|c| c.kind == BlobKind::Base64));
}

// ---------------------------------------------------------------------------
// "Magic present, payload broken" — the Medium leaves
// ---------------------------------------------------------------------------

/// XML plist markup that does not parse is still reported (Medium) with the parse
/// error, rather than dropped: the markers are strong enough evidence that the
/// analyst should see a truncated/corrupt plist.
#[test]
fn broken_xml_plist_is_reported_medium_with_the_parse_error() {
    let broken = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict><key>unclosed</key>
"#;
    let c = candidate_of(broken, BlobKind::XmlPlist);
    assert_eq!(c.score, Confidence::Medium);
    assert!(
        c.summary.starts_with("XML plist markup but parse failed:"),
        "summary must name the failure: {}",
        c.summary
    );
}

/// A V8 stream whose first value tag is valid but whose payload is truncated is
/// reported Medium and names the decode error — it opened as V8, so silence would
/// hide a real (if damaged) structured-clone artifact.
#[test]
fn truncated_v8_stream_is_reported_medium_with_the_decode_error() {
    // FF 0F      version header
    // 53 64      'S' kUtf8String declaring 100 bytes, with none following
    let truncated = [0xFF, 0x0F, 0x53, 0x64];
    let c = candidate_of(&truncated, BlobKind::V8Serialized);
    assert_eq!(c.score, Confidence::Medium);
    assert!(
        c.summary
            .starts_with("V8 structured-clone value header but decode failed:"),
        "summary must name the failure: {}",
        c.summary
    );
    assert!(c.summary.contains("truncated"), "{}", c.summary);
}

/// A `0xFF`-led blob whose first value tag is NOT a V8 tag is not claimed at all —
/// the guard that stops random binaries being mislabelled as structured clones.
#[test]
fn ff_led_non_v8_binary_is_not_claimed() {
    let not_v8 = [0xFF, 0x00, 0x01, 0x02, 0x03];
    let cands = identify(&not_v8);
    assert!(
        !cands
            .iter()
            .any(|c| matches!(c.kind, BlobKind::V8Serialized | BlobKind::BlinkSerialized)),
        "must not claim V8 for a non-V8 tag: {cands:?}"
    );
}

// ---------------------------------------------------------------------------
// UTF-16LE heuristic
// ---------------------------------------------------------------------------

fn utf16le_bytes(s: &str, bom: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if bom {
        out.extend_from_slice(&[0xff, 0xfe]);
    }
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// A BOM is strong evidence, so BOM'd UTF-16LE scores Medium and the preview shows
/// the decoded text (the BOM itself is not part of it).
#[test]
fn bom_prefixed_utf16le_scores_medium() {
    let bytes = utf16le_bytes("hello", true);
    let c = candidate_of(&bytes, BlobKind::Utf16Le);
    assert_eq!(c.score, Confidence::Medium);
    assert_eq!(c.summary, "UTF-16LE text preview: \"hello\"");
}

/// Without a BOM the reading is a coincidence-prone heuristic, so it scores Low even
/// though the text decodes cleanly.
#[test]
fn bomless_ascii_plane_utf16le_scores_low() {
    let bytes = utf16le_bytes("hello", false);
    let c = candidate_of(&bytes, BlobKind::Utf16Le);
    assert_eq!(c.score, Confidence::Low);
    assert_eq!(c.summary, "UTF-16LE text preview: \"hello\"");
}

/// Without a BOM, the ASCII-plane dominance test is what keeps even-length binary
/// from masquerading as text. Real UTF-16LE outside the ASCII plane (CJK) fails that
/// test and is deliberately NOT claimed — the honest trade-off: a false negative on
/// bomless CJK beats a false positive on every even-length blob.
#[test]
fn bomless_non_ascii_plane_utf16le_is_not_claimed() {
    let bytes = utf16le_bytes("中文中文", false);
    assert_eq!(bytes.len() % 2, 0);
    let cands = identify(&bytes);
    assert!(
        !cands.iter().any(|c| c.kind == BlobKind::Utf16Le),
        "bomless non-ASCII-plane text must not be claimed: {cands:?}"
    );
    // With a BOM the same text IS claimed — proving the ASCII-plane test, not the
    // decode, is what rejected it.
    let with_bom = utf16le_bytes("中文中文", true);
    assert_eq!(
        candidate_of(&with_bom, BlobKind::Utf16Le).score,
        Confidence::Medium
    );
}

// ---------------------------------------------------------------------------
// Protobuf structure inference
// ---------------------------------------------------------------------------

/// A length-delimited field whose payload is neither valid UTF-8 nor a parseable
/// submessage is inferred as opaque *bytes* — no corroborating structure, so the
/// reading stays Low and the counts report zero submessages and zero strings.
#[test]
fn opaque_length_delimited_field_counts_as_neither_string_nor_submessage() {
    // field 1, wire type 2 (0x0A), length 3, then bytes that are not UTF-8 and
    // whose first byte (0xFF -> field 31, wire type 7) is an invalid tag.
    let bytes = [0x0A, 0x03, 0xFF, 0xFE, 0xFD];
    let c = candidate_of(&bytes, BlobKind::Protobuf);
    assert_eq!(c.score, Confidence::Low);
    assert!(
        c.summary.contains("(0 submessages, 0 strings)"),
        "opaque bytes must corroborate nothing: {}",
        c.summary
    );
}

// ---------------------------------------------------------------------------
// plist root-type descriptions
// ---------------------------------------------------------------------------

fn xml_plist(body: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">{body}</plist>\n"
    )
    .into_bytes()
}

fn xml_plist_summary(body: &str) -> String {
    let bytes = xml_plist(body);
    let c = candidate_of(&bytes, BlobKind::XmlPlist);
    assert_eq!(c.score, Confidence::High, "{}", c.summary);
    c.summary
}

/// Every plist root type an XML plist can carry is described by name, so the
/// candidate summary tells the analyst what the root actually is.
#[test]
fn every_xml_plist_root_type_is_described() {
    assert_eq!(
        xml_plist_summary("<array><integer>1</integer><integer>2</integer></array>"),
        "XML plist: array with 2 items"
    );
    assert_eq!(
        xml_plist_summary("<dict><key>a</key><integer>1</integer></dict>"),
        "XML plist: dict with 1 entries"
    );
    assert_eq!(xml_plist_summary("<true/>"), "XML plist: boolean");
    assert_eq!(xml_plist_summary("<false/>"), "XML plist: boolean");
    // "aGk=" is base64 for "hi" -> 2 bytes of data.
    assert_eq!(
        xml_plist_summary("<data>aGk=</data>"),
        "XML plist: data (2 bytes)"
    );
    assert_eq!(
        xml_plist_summary("<date>2024-01-01T00:00:00Z</date>"),
        "XML plist: date"
    );
    assert_eq!(xml_plist_summary("<real>1.5</real>"), "XML plist: real");
    assert_eq!(
        xml_plist_summary("<integer>42</integer>"),
        "XML plist: integer"
    );
    assert_eq!(
        xml_plist_summary("<string>hi</string>"),
        "XML plist: string"
    );
}

/// A `UID` object appears only in the *binary* encoding (NSKeyedArchiver's
/// `CF$UID` references), so the fixture is minted in-test by the `plist` crate's
/// binary writer — the reference implementation, making the root type ground truth.
#[test]
fn binary_plist_uid_root_is_described() {
    let mut bytes = Vec::new();
    plist::Value::Uid(plist::Uid::new(1))
        .to_writer_binary(&mut bytes)
        .expect("plist binary writer must emit a UID root");
    assert!(
        bytes.starts_with(b"bplist"),
        "not a binary plist: {bytes:?}"
    );

    let c = candidate_of(&bytes, BlobKind::BinaryPlist);
    assert_eq!(c.score, Confidence::High);
    assert_eq!(c.summary, "binary plist: uid");
}
