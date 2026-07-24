# 2. Delegate every decode to the crate that owns the format; own only orchestration

Date: 2026-07-24
Status: Accepted

## Context

Each format blob-decoder recognises already has a mature, widely-used Rust crate
that is effectively the reference implementation for that format: `plist` (Apple
property lists), `flate2` (gzip/zlib/deflate), `snap` (Snappy), `base64`, `hex`,
`uuid`, `serde_json`. Reimplementing any of these would add a large, untrusted
parsing surface for zero benefit — the exact failure the Research-First and
DRY-via-search-first disciplines exist to prevent (the "LZNT1 trap": a hand-rolled
codec that ships green against its own fixtures while being wrong on real data).

## Decision

blob-decoder writes **no codec of its own**. Every detector in `src/identify.rs` is
a thin dispatcher that hands the bytes to the crate that owns the format and
interprets the result:

- `detect_binary_plist` / `detect_xml_plist` → `plist::Value::from_reader`
- `detect_gzip` / `detect_zlib` → `flate2::read::{GzDecoder,ZlibDecoder}`
- `detect_snappy` → `snap::read::FrameDecoder`
- `detect_json` → `serde_json::from_slice`
- `detect_base64` → the `base64` crate engines; `detect_hex` → `hex::decode`
- `detect_uuid_string` / `detect_uuid_bytes` → `uuid::Uuid`

The crate owns only the layer none of those provides: **identification** (which
detector to believe), **scoring** (how strongly), and **recursive unwrap** (chaining
a wrapper's decoded payload back through the same engine). The module docstring
states it: *"Every detector here is a thin dispatcher over a mature crate … this
module owns only the identification, scoring, and recursive unwrap, never the codec
itself."*

## Consequences

- Correctness of each decode inherits from the upstream crate's own testing and its
  large real-world corpus; validation focuses on the orchestration layer this crate
  adds (see `docs/validation.md`).
- The dependency list is the capability list — adding a format means adding its
  owning crate and one dispatcher, not a new parser.
- Upstream advisories/bumps flow through `cargo deny` + Renovate rather than needing
  in-house maintenance of codec internals.
