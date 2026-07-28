#![allow(clippy::unwrap_used, clippy::expect_used)]
// The `double_pi` fixture's JS input value is literally `3.14` — asserting the
// exact decoded double is the point, so the near-PI lint does not apply here.
#![allow(clippy::approx_constant)]
//! Tier-2 oracle: real V8 `ValueSerializer` output (minted by node's
//! `v8.serialize`; see tests/data/README.md + scripts/mint_v8_fixtures.mjs). The
//! **known JS input value is the ground truth** — the deserializer must reproduce
//! it. Every fixture is a distinct `SerializationTag` path.

use blob_decoder::v8_value::{deserialize, V8Value};
use blob_decoder::{identify, BlobKind, Confidence};

macro_rules! v8 {
    ($name:literal) => {
        include_bytes!(concat!("data/v8/", $name, ".v8"))
    };
}

fn s(x: &str) -> V8Value {
    V8Value::String(x.to_owned())
}

#[test]
fn primitives() {
    assert_eq!(deserialize(v8!("undefined")).unwrap(), V8Value::Undefined);
    assert_eq!(deserialize(v8!("null")).unwrap(), V8Value::Null);
    assert_eq!(deserialize(v8!("bool_true")).unwrap(), V8Value::Bool(true));
    assert_eq!(
        deserialize(v8!("bool_false")).unwrap(),
        V8Value::Bool(false)
    );
}

#[test]
fn integers() {
    assert_eq!(deserialize(v8!("int_42")).unwrap(), V8Value::Int(42));
    assert_eq!(deserialize(v8!("int_neg7")).unwrap(), V8Value::Int(-7));
    assert_eq!(deserialize(v8!("int_zero")).unwrap(), V8Value::Int(0));
}

#[test]
fn doubles() {
    assert_eq!(
        deserialize(v8!("double_pi")).unwrap(),
        V8Value::Double(3.14)
    );
    assert_eq!(
        deserialize(v8!("double_neg")).unwrap(),
        V8Value::Double(-2.5)
    );
    // 4_000_000_000 exceeds i32 range → V8 serializes it as a double, not kInt32.
    assert_eq!(
        deserialize(v8!("uint_big")).unwrap(),
        V8Value::Double(4_000_000_000.0)
    );
}

#[test]
fn strings() {
    assert_eq!(deserialize(v8!("string_ascii")).unwrap(), s("hello"));
    assert_eq!(deserialize(v8!("string_empty")).unwrap(), s(""));
    // kTwoByteString (UTF-16LE): Latin-1 accents, an arrow, and CJK.
    assert_eq!(deserialize(v8!("string_unicode")).unwrap(), s("héllo→世界"));
}

#[test]
fn bigints() {
    assert_eq!(
        deserialize(v8!("bigint_pos")).unwrap(),
        V8Value::BigInt("123456789012345678901234567890".to_owned())
    );
    assert_eq!(
        deserialize(v8!("bigint_neg")).unwrap(),
        V8Value::BigInt("-42".to_owned())
    );
}

#[test]
fn date() {
    assert_eq!(
        deserialize(v8!("date")).unwrap(),
        V8Value::Date(1_600_000_000_000.0)
    );
}

#[test]
fn arrays() {
    assert_eq!(
        deserialize(v8!("array_ints")).unwrap(),
        V8Value::Array(vec![V8Value::Int(1), V8Value::Int(2), V8Value::Int(3)])
    );
    assert_eq!(
        deserialize(v8!("array_mixed")).unwrap(),
        V8Value::Array(vec![
            V8Value::Int(1),
            s("two"),
            V8Value::Bool(true),
            V8Value::Null,
        ])
    );
    assert_eq!(
        deserialize(v8!("array_empty")).unwrap(),
        V8Value::Array(vec![])
    );
    // Sparse array: `const a = [1]; a[3] = 4` → [1, <hole>, <hole>, 4].
    assert_eq!(
        deserialize(v8!("array_holes")).unwrap(),
        V8Value::Array(vec![
            V8Value::Int(1),
            V8Value::Hole,
            V8Value::Hole,
            V8Value::Int(4),
        ])
    );
}

#[test]
fn objects() {
    assert_eq!(
        deserialize(v8!("object_simple")).unwrap(),
        V8Value::Object(vec![
            ("a".to_owned(), V8Value::Int(1)),
            ("b".to_owned(), s("two")),
            ("c".to_owned(), V8Value::Bool(true)),
        ])
    );
    assert_eq!(
        deserialize(v8!("object_empty")).unwrap(),
        V8Value::Object(vec![])
    );
    assert_eq!(
        deserialize(v8!("object_nested")).unwrap(),
        V8Value::Object(vec![
            ("name".to_owned(), s("x")),
            (
                "list".to_owned(),
                V8Value::Array(vec![
                    V8Value::Int(1),
                    V8Value::Int(2),
                    V8Value::Object(vec![("deep".to_owned(), s("y"))]),
                ])
            ),
            ("when".to_owned(), V8Value::Date(1_600_000_000_000.0)),
        ])
    );
}

#[test]
fn maps_and_sets() {
    assert_eq!(
        deserialize(v8!("map")).unwrap(),
        V8Value::Map(vec![(s("k1"), V8Value::Int(1)), (s("k2"), V8Value::Int(2)),])
    );
    assert_eq!(
        deserialize(v8!("set")).unwrap(),
        V8Value::Set(vec![V8Value::Int(1), V8Value::Int(2), V8Value::Int(3)])
    );
}

#[test]
fn regexp() {
    assert_eq!(
        deserialize(v8!("regexp")).unwrap(),
        V8Value::RegExp {
            source: "ab+c".to_owned(),
            flags: 3, // global | ignoreCase
        }
    );
}

#[test]
fn boxed_primitive_objects() {
    assert_eq!(
        deserialize(v8!("number_object")).unwrap(),
        V8Value::NumberObject(7.0)
    );
    assert_eq!(
        deserialize(v8!("string_object")).unwrap(),
        V8Value::StringObject("wrap".to_owned())
    );
    assert_eq!(
        deserialize(v8!("boolean_object")).unwrap(),
        V8Value::BooleanObject(true)
    );
}

#[test]
fn arraybuffer() {
    assert_eq!(
        deserialize(v8!("arraybuffer")).unwrap(),
        V8Value::ArrayBuffer(vec![1, 2, 3, 4])
    );
}

#[test]
fn shared_reference_is_resolved() {
    // `[o, o]` where both elements are the same object → kObjectReference back to
    // the first. The decoder resolves the reference to an equal value.
    let obj = V8Value::Object(vec![("v".to_owned(), V8Value::Int(1))]);
    assert_eq!(
        deserialize(v8!("shared_ref")).unwrap(),
        V8Value::Array(vec![obj.clone(), obj])
    );
}

#[test]
fn host_objects_fail_loud() {
    // node serializes typed arrays through its own kHostObject (0x5C) delegate —
    // not a standard V8/Blink structure. The decoder must fail loudly (surface the
    // tag), never fabricate a decode.
    let err = deserialize(v8!("uint8array")).unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("host"),
        "expected a host-object error, got: {err}"
    );
    assert!(deserialize(v8!("int32array")).is_err());
}

#[test]
fn identify_surfaces_v8() {
    let cands = identify(v8!("object_simple"));
    assert_eq!(cands[0].kind, BlobKind::V8Serialized);
    assert_eq!(cands[0].score, Confidence::High);
}

#[test]
fn truncated_input_does_not_panic() {
    let full = v8!("object_nested");
    for cut in 0..full.len() {
        // Every prefix must return Ok or Err — never panic.
        let _ = deserialize(&full[..cut]);
    }
}
