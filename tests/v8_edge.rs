#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tier-2 hand-built V8 `ValueSerializer` streams for tag/handler paths that the
//! node-minted fixtures don't exercise (modern V8 prefers one-byte strings, and
//! never re-references a Map). Each byte sequence is assembled directly from the
//! documented wire format (`src/objects/value-serializer.cc`): a `0xFF` version
//! header, then one-byte serialization tags with LEB128-varint lengths and
//! zig-zag `kInt32`. The **constructed structure is the ground truth**.

use blob_decoder::v8_value::{deserialize, V8Value};

/// `kUtf8String` (`S`): a byte-length varint then raw UTF-8. V8 emits this for
/// strings it stores as UTF-8 (the node fixtures all land on one-/two-byte
/// strings, so this tag path needs a purpose-built stream).
#[test]
fn utf8_string_tag_decodes() {
    // FF 0F            version header (v15)
    // 53 02 68 69      'S' len=2 "hi"
    let bytes = [0xFF, 0x0F, 0x53, 0x02, 0x68, 0x69];
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::String("hi".to_owned())
    );
}

/// A `kObjectReference` (`^`) pointing back at a previously serialized **Map**.
/// Resolving the reference re-materializes the map, charging its node count —
/// which walks the map's key/value entries (the sparse-array/object shared-ref
/// fixtures never reference a Map, so this is the only path over that arm).
#[test]
fn shared_reference_to_map_is_resolved() {
    // FF 0F                     version header
    // 41 02                     'A' begin dense array, length 2
    //   3B                        ';' begin map            -> id 1 (array is id 0)
    //     49 02                     'I' int32 zig-zag(2)=1  (key)
    //     49 04                     'I' int32 zig-zag(4)=2  (value)
    //   3A 02                     ':' end map, count=2 (2 * 1 entry)
    //   5E 01                     '^' object reference to id 1 (the map)
    // 24 00 02                  '$' end dense array, num_props=0, length=2
    let bytes = [
        0xFF, 0x0F, 0x41, 0x02, 0x3B, 0x49, 0x02, 0x49, 0x04, 0x3A, 0x02, 0x5E, 0x01, 0x24, 0x00,
        0x02,
    ];
    let map = V8Value::Map(vec![(V8Value::Int(1), V8Value::Int(2))]);
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Array(vec![map.clone(), map])
    );
}

/// `V8Value::summary` ellipsizes long strings to a 32-char head plus `…`, and
/// leaves short ones intact. Exercises both branches of the truncation helper.
#[test]
fn summary_ellipsizes_long_strings() {
    let short = V8Value::String("hello".to_owned()).summary();
    assert!(short.contains("hello"));
    assert!(
        !short.contains('…'),
        "short string must not be truncated: {short}"
    );

    let long = V8Value::String("a".repeat(40)).summary();
    assert!(
        long.contains('…'),
        "40-char string must be ellipsized: {long}"
    );
}
