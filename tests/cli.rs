#![allow(clippy::unwrap_used, clippy::expect_used)]
//! CLI contract for `blob-decode` (a thin Humble-Object shell): input sources
//! (--string / --hex / --base64 / file / stdin), human + JSON output, and
//! pipeline-safe exit codes (0 identified, 2 unknown, 1 error).

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_blob-decode"))
}

#[test]
fn string_input_identifies_json_human() {
    let out = bin().args(["--string", "{\"a\":1}"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(s.contains("json"), "stdout: {s}");
}

#[test]
fn json_output_is_valid_json_array() {
    let out = bin()
        .args(["--string", "[1,2,3]", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(v.is_array());
}

#[test]
fn stdin_is_read_when_no_source_given() {
    let mut child = bin()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{\"a\":1}").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout)
        .to_lowercase()
        .contains("json"));
}

#[test]
fn unknown_input_exits_2() {
    // 0xDEADBEEF: four bytes, no known type → Unknown → exit 2.
    let out = bin().args(["--hex", "deadbeef"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn invalid_hex_exits_1() {
    let out = bin().args(["--hex", "zzzz"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr)
        .to_lowercase()
        .contains("hex"));
}
