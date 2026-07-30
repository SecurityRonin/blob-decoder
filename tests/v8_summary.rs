#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [`V8Value::summary`] renders every decoded variant. The summary line is what an
//! analyst actually reads in a candidate, so each variant's exact rendering is
//! asserted — including the two pluralization forms (`entry`/`entries` for a Map,
//! `s` elsewhere), which a one-element and a two-element container exercise.

use blob_decoder::v8_value::V8Value;

#[test]
fn scalar_variants_render() {
    assert_eq!(V8Value::Undefined.summary(), "undefined");
    assert_eq!(V8Value::Null.summary(), "null");
    assert_eq!(V8Value::Hole.summary(), "hole");
    assert_eq!(V8Value::Bool(true).summary(), "boolean true");
    assert_eq!(V8Value::Bool(false).summary(), "boolean false");
    assert_eq!(V8Value::Int(-7).summary(), "integer -7");
    assert_eq!(V8Value::Double(1.5).summary(), "number 1.5");
    assert_eq!(V8Value::BigInt("-42".to_owned()).summary(), "bigint -42n");
    assert_eq!(V8Value::String("hi".to_owned()).summary(), "string \"hi\"");
    assert_eq!(V8Value::Date(1000.0).summary(), "date (1000 ms)");
}

#[test]
fn regexp_renders_source_and_raw_flag_bits() {
    let v = V8Value::RegExp {
        source: "ab+c".to_owned(),
        flags: 3,
    };
    assert_eq!(v.summary(), "regexp /ab+c/ (flags 3)");
}

/// A long regexp source is ellipsized by the same 32-char helper the string arm
/// uses, so a crafted multi-megabyte pattern cannot blow up the summary line.
#[test]
fn regexp_source_is_ellipsized() {
    let v = V8Value::RegExp {
        source: "x".repeat(64),
        flags: 0,
    };
    let s = v.summary();
    assert!(s.contains('…'), "long source must be ellipsized: {s}");
}

#[test]
fn container_variants_render_with_counts() {
    assert_eq!(V8Value::Array(vec![]).summary(), "array (0 elements)");
    assert_eq!(
        V8Value::Array(vec![V8Value::Null]).summary(),
        "array (1 element)"
    );
    assert_eq!(
        V8Value::Array(vec![V8Value::Null, V8Value::Null]).summary(),
        "array (2 elements)"
    );

    assert_eq!(
        V8Value::Object(vec![("k".to_owned(), V8Value::Null)]).summary(),
        "object (1 key)"
    );

    assert_eq!(V8Value::Map(vec![]).summary(), "map (0 entries)");
    assert_eq!(
        V8Value::Map(vec![(V8Value::Int(1), V8Value::Int(2))]).summary(),
        "map (1 entry)"
    );
    assert_eq!(
        V8Value::Map(vec![
            (V8Value::Int(1), V8Value::Int(2)),
            (V8Value::Int(3), V8Value::Int(4)),
        ])
        .summary(),
        "map (2 entries)"
    );

    assert_eq!(
        V8Value::Set(vec![V8Value::Int(1)]).summary(),
        "set (1 member)"
    );
    assert_eq!(
        V8Value::Set(vec![V8Value::Int(1), V8Value::Int(2)]).summary(),
        "set (2 members)"
    );

    assert_eq!(
        V8Value::ArrayBuffer(vec![0xAA]).summary(),
        "arraybuffer (1 byte)"
    );
    assert_eq!(
        V8Value::ArrayBuffer(vec![0xAA, 0xBB]).summary(),
        "arraybuffer (2 bytes)"
    );
}

/// Boxed primitives keep their wrapper identity in the summary, so `new Number(7)`
/// never reads as the bare number `7`.
#[test]
fn boxed_primitive_variants_render_their_wrapper() {
    assert_eq!(V8Value::NumberObject(7.0).summary(), "Number(7)");
    assert_eq!(
        V8Value::StringObject("x".to_owned()).summary(),
        "String(\"x\")"
    );
    assert_eq!(V8Value::BooleanObject(true).summary(), "Boolean(true)");
    assert_eq!(V8Value::BooleanObject(false).summary(), "Boolean(false)");
    assert_eq!(V8Value::BigIntObject("9".to_owned()).summary(), "BigInt(9)");
}
