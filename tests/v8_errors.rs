#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tier-2 hand-crafted **hostile** V8 streams: one per typed [`V8Error`] arm.
//!
//! This crate parses attacker-controllable IndexedDB / `postMessage` bytes, so the
//! failure paths are the security-relevant ones: a crafted blob must fail *loud*
//! with the offending value and offset (never panic, never OOM, never fabricate a
//! reading). Each byte sequence below is assembled directly from the documented
//! wire format (V8 `src/objects/value-serializer.cc`, Blink
//! `serialization/serialization_tag.h`); the **constructed structure is the ground
//! truth**, and the assertion is on the exact typed error — its offset, its cap,
//! and the offending tag/length — not merely that "an error happened".

use blob_decoder::v8_value::{
    deserialize, deserialize_blink, deserialize_with_limits, V8Error, V8Limits,
};

/// No `0xFF` version tag: the stream is not V8 at all, and the error names the byte
/// that *was* there (the "show the unrecognized value" rule).
#[test]
fn missing_version_header_names_the_offending_byte() {
    assert_eq!(
        deserialize(&[0x42, 0x5F]).unwrap_err(),
        V8Error::BadVersion {
            offset: 0,
            found: 0x42
        }
    );
}

/// An empty buffer is truncated before the version tag can be read.
#[test]
fn empty_input_is_truncated_not_a_panic() {
    assert_eq!(
        deserialize(&[]).unwrap_err(),
        V8Error::Truncated {
            offset: 0,
            needed: 1,
            available: 0
        }
    );
}

/// A varint of nothing but continuation bytes (high bit set) runs past the 64-bit
/// shift budget. Ten `0x80`s push `shift` to 70, so the 11th iteration trips the
/// cap instead of shifting out of range.
#[test]
fn unterminated_varint_is_rejected_at_the_shift_cap() {
    let mut bytes = vec![0xFF];
    bytes.extend_from_slice(&[0x80; 10]);
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::BadVarint { offset: 1 }
    );
}

/// A legitimate multi-byte varint still decodes: `0x80 0x01` is LEB128 for 128, so
/// a version-128 header is accepted (the reader is forward-compatible on version).
#[test]
fn multibyte_varint_version_header_is_accepted() {
    // FF 80 01   version header, version = 128 (two-byte LEB128)
    // 5F         '_' undefined
    let bytes = [0xFF, 0x80, 0x01, 0x5F];
    assert_eq!(
        deserialize(&bytes).unwrap(),
        blob_decoder::v8_value::V8Value::Undefined
    );
}

/// An unknown tag byte is reported verbatim with its offset, never silently
/// skipped: `0x01` introduces no V8 value.
#[test]
fn unknown_tag_is_surfaced_with_its_byte_and_offset() {
    let bytes = [0xFF, 0x0F, 0x01];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::UnsupportedTag {
            offset: 2,
            tag: 0x01
        }
    );
}

/// `kStringObject` (`s`) must wrap a string. A crafted stream that boxes an integer
/// instead is rejected, naming the `s` tag that opened the bad value.
#[test]
fn string_object_wrapping_a_non_string_is_rejected() {
    // FF 0F   version
    // 73      's' kStringObject   -> offset 2
    // 49 02   'I' int32 zig-zag(2) = 1   (not a string)
    let bytes = [0xFF, 0x0F, 0x73, 0x49, 0x02];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::UnsupportedTag {
            offset: 2,
            tag: b's'
        }
    );
}

/// `kTwoByteString` (`c`) declares a **byte** length; an odd one cannot be whole
/// UTF-16 code units, so the reader refuses rather than dropping a half unit.
#[test]
fn odd_length_two_byte_string_is_rejected() {
    // FF 0F         version
    // 63 03         'c' kTwoByteString, byte length 3 (odd)
    // 41 00 42      the three bytes
    let bytes = [0xFF, 0x0F, 0x63, 0x03, 0x41, 0x00, 0x42];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::OddUtf16 { offset: 3, len: 3 }
    );
}

/// A dense array must close with `kEndDenseJSArray` (`$`). A crafted stream that
/// closes with something else is rejected, naming the byte found in its place —
/// otherwise the reader would silently desynchronize.
#[test]
fn dense_array_without_its_end_tag_is_rejected() {
    // FF 0F      version
    // 41 01      'A' begin dense array, length 1
    // 5F         '_' undefined  (the one element)
    // 00         not '$' -> rejected at offset 5
    let bytes = [0xFF, 0x0F, 0x41, 0x01, 0x5F, 0x00];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::UnsupportedTag {
            offset: 5,
            tag: 0x00
        }
    );
}

/// A `kRegExp` source must be a string; anything else is a bad key/source value.
#[test]
fn regexp_with_a_non_string_source_is_rejected() {
    // FF 0F   version
    // 52      'R' kRegExp   (source read starts at offset 3)
    // 49 02   'I' int32 1   (not a string)
    let bytes = [0xFF, 0x0F, 0x52, 0x49, 0x02];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::BadKey { offset: 3 }
    );
}

/// A property key must be a string or a number. A `null` key is neither, so the
/// object read fails loud instead of inventing a key name.
#[test]
fn object_with_a_null_property_key_is_rejected() {
    // FF 0F   version
    // 6F      'o' begin object   (first key read starts at offset 3)
    // 30      '0' null           (an illegal key)
    let bytes = [0xFF, 0x0F, 0x6F, 0x30];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::BadKey { offset: 3 }
    );
}

/// A dangling `kObjectReference` (`^`) to an id that was never assigned is
/// reported with the id, not resolved to some nearby object.
#[test]
fn dangling_object_reference_names_the_id() {
    // FF 0F      version
    // 5E 07      '^' object reference to id 7 (nothing has been assigned)
    let bytes = [0xFF, 0x0F, 0x5E, 0x07];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::BadReference { offset: 3, id: 7 }
    );
}

/// The node budget is the reference-amplification / allocation guard. A Set
/// declares no length, so the budget — not a length field — is what stops it: the
/// Set itself consumes the single node, and its first member trips the cap.
#[test]
fn node_cap_stops_a_budget_exhausting_stream() {
    let limits = V8Limits {
        max_depth: 256,
        max_nodes: 1,
    };
    // FF 0F      version
    // 27         '\'' begin set   (charges the one available node)
    // 5F         '_' undefined    (the member that exceeds the budget)
    // 2C 01      ',' end set, count 1
    let bytes = [0xFF, 0x0F, 0x27, 0x5F, 0x2C, 0x01];
    assert_eq!(
        deserialize_with_limits(&bytes, limits).unwrap_err(),
        V8Error::NodeCap { cap: 1 }
    );
}

/// A declared length larger than the node cap is rejected **before** allocating —
/// the decompression-bomb equivalent for a lying length field. The error carries
/// the declared length and the cap it exceeded.
#[test]
fn declared_length_over_the_cap_is_rejected_before_allocating() {
    let limits = V8Limits {
        max_depth: 256,
        max_nodes: 4,
    };
    // FF 0F      version
    // 53 64      'S' kUtf8String, declared length 100 (> cap 4), no bytes follow
    let bytes = [0xFF, 0x0F, 0x53, 0x64];
    assert_eq!(
        deserialize_with_limits(&bytes, limits).unwrap_err(),
        V8Error::LengthCap {
            offset: 4,
            len: 100,
            cap: 4
        }
    );
}

/// The depth cap is the stack-overflow guard. With `max_depth: 0` the root value is
/// still read, but stepping into the array's first element exceeds the cap.
#[test]
fn depth_cap_stops_a_nested_stream() {
    let limits = V8Limits {
        max_depth: 0,
        max_nodes: 1000,
    };
    let bytes = [0xFF, 0x0F, 0x41, 0x01, 0x5F, 0x24, 0x00, 0x01];
    assert_eq!(
        deserialize_with_limits(&bytes, limits).unwrap_err(),
        V8Error::DepthCap { offset: 4, cap: 0 }
    );
}

/// A `kHostObject` (`\`) is an embedder value this decoder deliberately does not
/// fabricate a reading for; the following Blink tag byte is surfaced so an analyst
/// can identify the DOM type themselves.
#[test]
fn host_object_surfaces_the_blink_tag() {
    let bytes = [0xFF, 0x0F, 0x5C, 0x7F];
    assert_eq!(
        deserialize(&bytes).unwrap_err(),
        V8Error::HostObject {
            offset: 2,
            blink_tag: 0x7F
        }
    );
}

/// The Blink envelope reader shares the same guards: a Blink header whose nested
/// payload is not a V8 stream reports the byte found where `0xFF` was expected.
#[test]
fn blink_envelope_with_a_bad_nested_header_names_the_byte() {
    // FF 15      Blink envelope, version 21
    // 41         not the nested 0xFF V8 version tag
    let bytes = [0xFF, 0x15, 0x41];
    assert_eq!(
        deserialize_blink(&bytes).unwrap_err(),
        V8Error::BadVersion {
            offset: 2,
            found: 0x41
        }
    );
}
