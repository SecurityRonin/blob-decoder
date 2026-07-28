#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tier-2 oracle: **real** Chromium IndexedDB values, captured verbatim from a
//! live headless-Chrome `file__0.indexeddb.leveldb` (see tests/data/README.md).
//! Each carries the Blink SerializedScriptValue envelope
//! (`FF 15` version + `FE` trailer + `FF 10` V8 payload); the **stored JS value
//! is the ground truth**.

use blob_decoder::v8_value::{deserialize_blink, V8Value};
use blob_decoder::{identify, BlobKind, Confidence};

const IDB_STRING: &[u8] = include_bytes!("data/blink/idb_string.blinkssv");
const IDB_ARRAY: &[u8] = include_bytes!("data/blink/idb_array.blinkssv");
const IDB_OBJECT: &[u8] = include_bytes!("data/blink/idb_object.blinkssv");

fn s(x: &str) -> V8Value {
    V8Value::String(x.to_owned())
}

#[test]
fn blink_string() {
    assert_eq!(deserialize_blink(IDB_STRING).unwrap(), s("hello"));
}

#[test]
fn blink_array() {
    assert_eq!(
        deserialize_blink(IDB_ARRAY).unwrap(),
        V8Value::Array(vec![V8Value::Int(1), V8Value::Int(2), V8Value::Int(3)])
    );
}

#[test]
fn blink_object() {
    // {name:'x', list:[1,2,{deep:'y'}], when:new Date(1600000000000), flag:true, count:42}
    assert_eq!(
        deserialize_blink(IDB_OBJECT).unwrap(),
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
            ("flag".to_owned(), V8Value::Bool(true)),
            ("count".to_owned(), V8Value::Int(42)),
        ])
    );
}

#[test]
fn identify_surfaces_blink() {
    let cands = identify(IDB_OBJECT);
    assert_eq!(cands[0].kind, BlobKind::BlinkSerialized);
    assert_eq!(cands[0].score, Confidence::High);
}

#[test]
fn truncated_blink_does_not_panic() {
    for cut in 0..IDB_OBJECT.len() {
        let _ = deserialize_blink(&IDB_OBJECT[..cut]);
    }
}
