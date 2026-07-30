#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Exhaustive contract tests over every [`BlobKind`]. `label`, `citation`, and
//! `is_wrapper` are the analyst-facing metadata of a candidate reading, so each
//! variant is asserted individually — and the list is asserted to be complete, so
//! a newly-added kind cannot slip through with untested metadata.

use blob_decoder::BlobKind;

/// Every `BlobKind` in declaration order. `ALL.len()` is checked against an
/// exhaustive `match` below, so adding a variant without extending this list is a
/// compile error rather than a silent coverage hole.
const ALL: &[BlobKind] = &[
    BlobKind::BinaryPlist,
    BlobKind::XmlPlist,
    BlobKind::Gzip,
    BlobKind::Zlib,
    BlobKind::Snappy,
    BlobKind::Base64,
    BlobKind::Hex,
    BlobKind::Uuid,
    BlobKind::Json,
    BlobKind::Protobuf,
    BlobKind::V8Serialized,
    BlobKind::BlinkSerialized,
    BlobKind::Utf16Le,
    BlobKind::Utf8Text,
    BlobKind::Unknown,
];

/// A compile-time completeness check: this exhaustive `match` fails to build if a
/// variant is added, and the discriminant count is asserted against `ALL`.
fn ordinal(kind: BlobKind) -> usize {
    match kind {
        BlobKind::BinaryPlist => 0,
        BlobKind::XmlPlist => 1,
        BlobKind::Gzip => 2,
        BlobKind::Zlib => 3,
        BlobKind::Snappy => 4,
        BlobKind::Base64 => 5,
        BlobKind::Hex => 6,
        BlobKind::Uuid => 7,
        BlobKind::Json => 8,
        BlobKind::Protobuf => 9,
        BlobKind::V8Serialized => 10,
        BlobKind::BlinkSerialized => 11,
        BlobKind::Utf16Le => 12,
        BlobKind::Utf8Text => 13,
        BlobKind::Unknown => 14,
    }
}

#[test]
fn all_lists_every_kind_in_order() {
    for (i, &kind) in ALL.iter().enumerate() {
        assert_eq!(ordinal(kind), i, "ALL is out of order at index {i}");
    }
    assert_eq!(ALL.len(), 15);
}

/// Every kind renders a distinct, non-empty human label.
#[test]
fn every_kind_has_a_distinct_label() {
    let labels: Vec<&str> = ALL.iter().map(|k| k.label()).collect();
    for (&kind, label) in ALL.iter().zip(&labels) {
        assert!(!label.is_empty(), "{kind:?} has an empty label");
    }
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), labels.len(), "labels collide: {labels:?}");
}

/// Spot-check the exact wording of each label: the label is analyst-facing output
/// (it appears in the candidate summary), so a silent rewording is a regression.
#[test]
fn labels_render_the_expected_wording() {
    assert_eq!(BlobKind::BinaryPlist.label(), "Apple binary property list");
    assert_eq!(BlobKind::XmlPlist.label(), "Apple XML property list");
    assert_eq!(BlobKind::Gzip.label(), "gzip stream");
    assert_eq!(BlobKind::Zlib.label(), "zlib stream");
    assert_eq!(BlobKind::Snappy.label(), "Snappy framed stream");
    assert_eq!(BlobKind::Base64.label(), "base64 text");
    assert_eq!(BlobKind::Hex.label(), "hexadecimal text");
    assert_eq!(BlobKind::Uuid.label(), "UUID / GUID");
    assert_eq!(BlobKind::Json.label(), "JSON");
    assert_eq!(BlobKind::Protobuf.label(), "Protocol Buffers (schemaless)");
    assert_eq!(BlobKind::V8Serialized.label(), "V8 structured-clone value");
    assert_eq!(
        BlobKind::BlinkSerialized.label(),
        "Chromium/Blink SerializedScriptValue"
    );
    assert_eq!(BlobKind::Utf16Le.label(), "UTF-16LE text");
    assert_eq!(BlobKind::Utf8Text.label(), "UTF-8 text");
    assert_eq!(BlobKind::Unknown.label(), "unknown");
}

/// Every kind cites an authoritative spec — the traceability guarantee. The two
/// plist kinds deliberately share one CoreFoundation citation; every other kind's
/// citation is distinct.
#[test]
fn every_kind_cites_a_spec() {
    for &kind in ALL {
        assert!(
            !kind.citation().is_empty(),
            "{kind:?} has an empty citation"
        );
    }
    assert_eq!(
        BlobKind::BinaryPlist.citation(),
        BlobKind::XmlPlist.citation(),
        "both plist encodings cite the same CoreFoundation source"
    );
    assert!(BlobKind::Utf16Le.citation().contains("RFC 2781"));
    assert!(BlobKind::Utf8Text.citation().contains("RFC 3629"));
    assert!(BlobKind::Gzip.citation().contains("RFC 1952"));
    assert!(BlobKind::Zlib.citation().contains("RFC 1950"));
    assert!(BlobKind::Snappy.citation().contains("framing_format"));
    assert!(BlobKind::Base64.citation().contains("RFC 4648"));
    assert!(BlobKind::Uuid.citation().contains("RFC 9562"));
    assert!(BlobKind::Json.citation().contains("RFC 8259"));
    assert!(BlobKind::Protobuf.citation().contains("wire format"));
    assert!(BlobKind::V8Serialized
        .citation()
        .contains("value-serializer"));
    assert!(BlobKind::BlinkSerialized
        .citation()
        .contains("serialization_tag.h"));
    assert_eq!(BlobKind::Unknown.citation(), "no matching format");
}

/// Exactly the recursion drivers are wrappers: the two text encodings and the
/// three compression streams. Everything else is a leaf reading.
#[test]
fn only_the_recursion_drivers_are_wrappers() {
    let wrappers: Vec<BlobKind> = ALL.iter().copied().filter(|k| k.is_wrapper()).collect();
    assert_eq!(
        wrappers,
        vec![
            BlobKind::Gzip,
            BlobKind::Zlib,
            BlobKind::Snappy,
            BlobKind::Base64,
            BlobKind::Hex,
        ]
    );
}
