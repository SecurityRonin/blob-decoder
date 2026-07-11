#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Schemaless protobuf identification. Real wire bytes come from the system
//! `protoc` (an independent oracle, env-gated); the scoring boundary is asserted
//! against protobuf's permissiveness — a bare successful parse is a WEAK signal,
//! so it is Low unless the message carries corroborating structure (submessages
//! or strings), which lifts it only to Medium, never above a magic-matched kind.

mod common;

use blob_decoder::{identify, BlobKind, Confidence};

/// A message with a submessage and a string field — the corroborated structure
/// that earns Medium. Bytes produced by `protoc`, decoded by the crate.
#[test]
fn structured_protobuf_from_protoc_is_medium() {
    let schema = "syntax = \"proto3\";\n\
        message Sub { int32 x = 1; }\n\
        message Msg { int32 id = 1; string name = 2; Sub sub = 3; }\n";
    let Some(bytes) =
        common::protoc_encode(schema, "Msg", "id: 150\nname: \"alice\"\nsub { x: 42 }\n")
    else {
        eprintln!("SKIP: protoc unavailable");
        return;
    };
    let cands = identify(&bytes);
    // Nothing else matches these raw wire bytes, so protobuf is the best reading.
    assert_eq!(cands[0].kind, BlobKind::Protobuf, "cands: {cands:?}");
    assert_eq!(
        cands[0].score,
        Confidence::Medium,
        "submessage + string is corroborating structure → Medium"
    );
    assert!(
        cands[0].summary.contains("field"),
        "summary describes the decoded fields, got: {}",
        cands[0].summary
    );
    assert!(
        cands[0].summary.contains("submessage") || cands[0].summary.contains("string"),
        "summary surfaces the structure, got: {}",
        cands[0].summary
    );
}

/// A message of only scalar (varint) fields — valid protobuf, but no corroborating
/// structure, so it stays Low despite parsing cleanly. Bytes from `protoc`.
#[test]
fn scalar_only_protobuf_from_protoc_is_low() {
    let schema = "syntax = \"proto3\";\nmessage M { int32 a = 1; int32 b = 2; int64 c = 3; }\n";
    let Some(bytes) = common::protoc_encode(schema, "M", "a: 1\nb: 2\nc: 300\n") else {
        eprintln!("SKIP: protoc unavailable");
        return;
    };
    let cands = identify(&bytes);
    let pb = cands
        .iter()
        .find(|c| c.kind == BlobKind::Protobuf)
        .expect("protobuf reading present");
    assert_eq!(
        pb.score,
        Confidence::Low,
        "scalar-only message is a weak signal → Low, not Medium"
    );
}

/// A hand-built single varint field (`field 1 = 150`). Valid protobuf, but a
/// lone opaque varint is exactly the coincidence-prone case → Low. (Tier-3: this
/// exercises our *scoring rule*, not the decode — the decode oracle is `protoc`.)
#[test]
fn single_varint_scores_low() {
    let bytes = [0x08u8, 0x96, 0x01];
    let cands = identify(&bytes);
    let pb = cands
        .iter()
        .find(|c| c.kind == BlobKind::Protobuf)
        .expect("protobuf reading present");
    assert_eq!(pb.score, Confidence::Low);
    assert!(pb.score < Confidence::Medium);
}

/// Protobuf must never outrank a magic-matched kind: a JSON object is High, so
/// any protobuf reading (if the bytes even parse) ranks strictly below it.
#[test]
fn json_is_not_outranked_by_protobuf() {
    let cands = identify(b"{\"a\":[1,2,3],\"b\":true}");
    assert_eq!(cands[0].kind, BlobKind::Json);
    assert_eq!(cands[0].score, Confidence::High);
    if let Some(pos) = cands.iter().position(|c| c.kind == BlobKind::Protobuf) {
        assert!(pos > 0, "protobuf must rank below JSON");
        assert!(cands[pos].score < Confidence::High);
    }
}

/// Even a structured protobuf drops to Low when a High-confidence kind already
/// matched — a corroborated protobuf reading never claims Medium next to gzip.
#[test]
fn structured_protobuf_capped_low_when_high_kind_present() {
    let Some(gz) = common::gzip(b"{\"nested\":true}") else {
        eprintln!("SKIP: gzip unavailable");
        return;
    };
    let cands = identify(&gz);
    assert_eq!(cands[0].kind, BlobKind::Gzip);
    if let Some(pb) = cands.iter().find(|c| c.kind == BlobKind::Protobuf) {
        assert!(
            pb.score < Confidence::Medium,
            "a High kind is present → protobuf capped at Low"
        );
    }
}
