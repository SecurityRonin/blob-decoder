//! Shared helpers for producing REAL blob inputs with independent, standard
//! tools (python3 `plistlib`/`zlib`, system `gzip`/`base64`/`uuidgen`). Every
//! producer is env-gated: when the tool is absent the test SKIPs cleanly rather
//! than failing (Test-Data Provenance: prefer real, tool-produced inputs over
//! self-authored fixtures — the producer is independent of the crate under test).

#![allow(dead_code)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// Run `program args…`, feed `input` on stdin, return stdout bytes. `None` if the
/// program is missing or exits non-zero (caller SKIPs the test).
pub fn run_piped(program: &str, args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(input).ok()?;
    let out = child.wait_with_output().ok()?;
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

/// Run `program args…` with no stdin, return stdout bytes.
pub fn run(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new(program).args(args).output().ok()?;
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

/// A binary plist of `{"a": 1, "b": [1, 2]}` produced by python3 `plistlib`.
pub fn bplist_dict() -> Option<Vec<u8>> {
    run(
        "python3",
        &[
            "-c",
            "import plistlib,sys; sys.stdout.buffer.write(plistlib.dumps({'a':1,'b':[1,2]}, fmt=plistlib.FMT_BINARY))",
        ],
    )
}

/// An XML plist of the same dict produced by python3 `plistlib`.
pub fn xml_plist_dict() -> Option<Vec<u8>> {
    run(
        "python3",
        &[
            "-c",
            "import plistlib,sys; sys.stdout.buffer.write(plistlib.dumps({'a':1,'b':[1,2]}, fmt=plistlib.FMT_XML))",
        ],
    )
}

/// zlib-compress `data` via python3 `zlib` (independent of flate2).
pub fn zlib_compress(data: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("python3")
        .args([
            "-c",
            "import sys,zlib; sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read()))",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

/// gzip-compress `data` via the system `gzip` (independent of flate2).
pub fn gzip(data: &[u8]) -> Option<Vec<u8>> {
    run_piped("gzip", &["-c"], data)
}

/// base64-encode `data` via the system `base64` (independent of the base64 crate).
pub fn base64(data: &[u8]) -> Option<Vec<u8>> {
    run_piped("base64", &[], data)
}

/// Encode a protobuf message to wire bytes with the system `protoc` — an
/// independent oracle for the protobuf decode path (never `protobuf-forensic-core`
/// itself). `schema` is a `.proto` source, `root_msg` its top-level message name,
/// and `text` a text-format instance fed on stdin. `None` if `protoc` is absent.
pub fn protoc_encode(schema: &str, root_msg: &str, text: &str) -> Option<Vec<u8>> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let uniq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("blobdec-protoc-{}-{uniq}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let proto = dir.join("schema.proto");
    std::fs::write(&proto, schema).ok()?;
    let result = (|| {
        let mut child = Command::new("protoc")
            .arg(format!("--encode={root_msg}"))
            .arg(format!("--proto_path={}", dir.display()))
            .arg(&proto)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(text.as_bytes()).ok()?;
        let out = child.wait_with_output().ok()?;
        out.status.success().then_some(out.stdout)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}
