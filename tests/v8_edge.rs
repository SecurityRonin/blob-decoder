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

/// `kTheHole` (`-`) as a root value: V8 emits it for an absent element, and the
/// reader surfaces it as a distinct value rather than conflating it with `undefined`
/// (a hole and an explicit `undefined` element are forensically different).
#[test]
fn the_hole_tag_decodes() {
    assert_eq!(deserialize(&[0xFF, 0x0F, b'-']).unwrap(), V8Value::Hole);
}

/// `kUint32` (`U`): a plain (non-zig-zag) varint, unlike `kInt32`. V8 uses it for
/// unsigned array indices, so decoding it as zig-zag would halve every value.
#[test]
fn uint32_tag_decodes_without_zigzag() {
    // FF 0F      version
    // 55 2A      'U' kUint32, varint 42 (a zig-zag read would yield 21)
    assert_eq!(
        deserialize(&[0xFF, 0x0F, 0x55, 0x2A]).unwrap(),
        V8Value::Int(42)
    );
}

/// `kFalseObject` (`x`) — `new Boolean(false)`. Distinct from the bare `kFalse`
/// tag, and it takes an object id (the boxed object has reference identity).
#[test]
fn false_object_tag_decodes() {
    assert_eq!(
        deserialize(&[0xFF, 0x0F, b'x']).unwrap(),
        V8Value::BooleanObject(false)
    );
}

/// `kBigIntObject` (`z`) — `Object(5n)`. The bitfield is `(byte_len << 1) | sign`,
/// so `0x02` means one magnitude byte, positive.
#[test]
fn bigint_object_tag_decodes() {
    // FF 0F      version
    // 7A         'z' kBigIntObject
    // 02         bitfield: byte_len 1, not negative
    // 05         the magnitude byte
    assert_eq!(
        deserialize(&[0xFF, 0x0F, 0x7A, 0x02, 0x05]).unwrap(),
        V8Value::BigIntObject("5".to_owned())
    );
}

/// A zero `kBigInt` has an empty magnitude and is never rendered `-0`: the sign bit
/// is ignored once the magnitude is zero.
#[test]
fn zero_bigint_is_never_negative() {
    // 00 -> bitfield 0: byte_len 0, not negative
    assert_eq!(
        deserialize(&[0xFF, 0x0F, b'Z', 0x00]).unwrap(),
        V8Value::BigInt("0".to_owned())
    );
    // 01 -> bitfield 1: byte_len 0, negative bit SET, magnitude still empty
    assert_eq!(
        deserialize(&[0xFF, 0x0F, b'Z', 0x01]).unwrap(),
        V8Value::BigInt("0".to_owned())
    );
}

/// A negative multi-byte `kBigInt`: bitfield `(2 << 1) | 1 = 5`, magnitude
/// `0x00 0x01` little-endian = 256, so the value is `-256`.
#[test]
fn negative_multibyte_bigint_decodes() {
    assert_eq!(
        deserialize(&[0xFF, 0x0F, b'Z', 0x05, 0x00, 0x01]).unwrap(),
        V8Value::BigInt("-256".to_owned())
    );
}

/// A dense array may carry trailing *named* properties after its `$` end tag
/// (`arr.foo = 1`). They are consumed to stay in sync with the stream but are not
/// attached to the positional elements.
#[test]
fn dense_array_trailing_named_properties_are_consumed() {
    // FF 0F            version
    // 41 01            'A' begin dense array, length 1
    //   5F               '_' undefined  (element 0)
    // 24 01            '$' end dense array, num_props = 1
    //   53 01 6B         'S' kUtf8String len 1 "k"   (property name)
    //   49 02            'I' int32 zig-zag(2) = 1    (property value)
    // 01               length repeated
    let bytes = [
        0xFF, 0x0F, 0x41, 0x01, 0x5F, 0x24, 0x01, 0x53, 0x01, 0x6B, 0x49, 0x02, 0x01,
    ];
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Array(vec![V8Value::Undefined])
    );
}

/// A sparse array's non-integer keys are named properties, not indices — they must
/// not be written into the positional array, which stays all holes.
#[test]
fn sparse_array_named_key_is_not_an_index() {
    // FF 0F            version
    // 61 01            'a' begin sparse array, length 1
    //   53 01 6B         'S' "k"        (a NAMED key, not an index)
    //   5F               '_' undefined  (its value)
    // 40 00 01         '@' end sparse array, num_props 0, length repeated
    let bytes = [
        0xFF, 0x0F, 0x61, 0x01, 0x53, 0x01, 0x6B, 0x5F, 0x40, 0x00, 0x01,
    ];
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Array(vec![V8Value::Hole])
    );
}

/// A sparse array with a **negative** integer key: `usize::try_from` rejects it, so
/// the element is dropped rather than wrapping around into an in-range index.
#[test]
fn sparse_array_negative_index_is_dropped() {
    // FF 0F            version
    // 61 01            'a' begin sparse array, length 1
    //   49 01            'I' int32 zig-zag(1) = -1  (a negative index)
    //   49 54            'I' int32 zig-zag(0x54) = 42
    // 40 00 01         '@' end sparse array, num_props 0, length repeated
    let bytes = [
        0xFF, 0x0F, 0x61, 0x01, 0x49, 0x01, 0x49, 0x54, 0x40, 0x00, 0x01,
    ];
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Array(vec![V8Value::Hole])
    );
}

/// A sparse array with an out-of-range positive index is likewise dropped: a lying
/// index must never write past the declared length.
#[test]
fn sparse_array_out_of_range_index_is_dropped() {
    // 49 0A -> zig-zag(10) = 5, but the declared length is 1
    let bytes = [
        0xFF, 0x0F, 0x61, 0x01, 0x49, 0x0A, 0x49, 0x54, 0x40, 0x00, 0x01,
    ];
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Array(vec![V8Value::Hole])
    );
}

/// V8 emits property keys as serialized values: strings, integer indices, and (for
/// a numeric-but-not-int32 key) doubles. All three render to a key *name*.
#[test]
fn integer_and_double_property_keys_render_as_names() {
    // FF 0F      version
    // 6F         'o' begin object
    //   49 02      'I' int32 zig-zag(2) = 1   (integer key -> "1")
    //   5F         '_' undefined
    //   4E ..      'N' double 1.5             (double key -> "1.5")
    //   30         '0' null
    // 7B 02      '{' end object, property count 2
    let mut bytes = vec![0xFF, 0x0F, 0x6F, 0x49, 0x02, 0x5F, 0x4E];
    bytes.extend_from_slice(&1.5f64.to_le_bytes());
    bytes.extend_from_slice(&[0x30, 0x7B, 0x02]);
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Object(vec![
            ("1".to_owned(), V8Value::Undefined),
            ("1.5".to_owned(), V8Value::Null),
        ])
    );
}

/// A `kObjectReference` (`^`) to a previously serialized **array** re-materializes
/// it and charges its recursive node count — the reference-amplification guard's
/// walk over the array/set arm of the node counter.
#[test]
fn shared_reference_to_array_is_resolved() {
    // FF 0F                  version
    // 41 02                  'A' begin dense array, length 2   -> id 0
    //   41 01 5F 24 00 01      a nested 1-element array [undefined] -> id 1
    //   5E 01                  '^' object reference to id 1
    // 24 00 02               '$' end dense array, num_props 0, length 2
    let bytes = [
        0xFF, 0x0F, 0x41, 0x02, 0x41, 0x01, 0x5F, 0x24, 0x00, 0x01, 0x5E, 0x01, 0x24, 0x00, 0x02,
    ];
    let inner = V8Value::Array(vec![V8Value::Undefined]);
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Array(vec![inner.clone(), inner])
    );
}

/// The same reference walk over a **Set**, whose node count shares the array arm.
#[test]
fn shared_reference_to_set_is_resolved() {
    // FF 0F                  version
    // 41 02                  'A' begin dense array, length 2   -> id 0
    //   27 5F 2C 01            '\'' begin set, undefined, ',' end, count 1 -> id 1
    //   5E 01                  '^' object reference to id 1
    // 24 00 02               '$' end dense array
    let bytes = [
        0xFF, 0x0F, 0x41, 0x02, 0x27, 0x5F, 0x2C, 0x01, 0x5E, 0x01, 0x24, 0x00, 0x02,
    ];
    let set = V8Value::Set(vec![V8Value::Undefined]);
    assert_eq!(
        deserialize(&bytes).unwrap(),
        V8Value::Array(vec![set.clone(), set])
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
