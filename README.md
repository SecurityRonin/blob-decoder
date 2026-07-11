# blob-decoder

[![Crates.io](https://img.shields.io/crates/v/blob-decoder.svg)](https://crates.io/crates/blob-decoder)
[![Docs.rs](https://img.shields.io/docsrs/blob-decoder)](https://docs.rs/blob-decoder)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/blob-decoder/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/blob-decoder/actions/workflows/ci.yml)
[![Fuzz](https://github.com/SecurityRonin/blob-decoder/actions/workflows/fuzz.yml/badge.svg)](https://github.com/SecurityRonin/blob-decoder/actions/workflows/fuzz.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**What is this blob? Hand it the bytes — get back what they are, decoded.**

Every examination turns up an opaque value — a column full of gibberish, a
property-list `Data` field, a config string that is obviously encoded but you are
not sure how. `blob-decoder` reads those bytes, **identifies** the type,
**decodes** it, and — the differentiator — **recursively unwraps nested
wrappers**, so a base64'd, gzip'd binary-plist comes back as the whole chain,
each link scored and cited. It never guesses one answer for an ambiguous blob; it
ranks every plausible reading by honest confidence.

```console
$ B64=$(printf '{"user":"alice"}' | gzip | base64 | tr -d '\n')
$ blob-decode --string "$B64"
blob-decode: 48 bytes; 2 candidate reading(s), best first:
  [MED ] base64 text — base64 text; decodes to 36 bytes
       cite: RFC 4648 §4-5 (Base 64 / Base64url)
       decodes to 36 bytes:
    [HIGH] gzip stream — gzip stream; 16 bytes decompressed
         cite: RFC 1952 (GZIP file format)
         decodes to 16 bytes:
      [HIGH] JSON — JSON object with 1 keys
           cite: RFC 8259 (JSON)
  [LOW ] UTF-8 text — UTF-8 text preview: "H4sIAD4mUWoAA6tWKi1OLVKyUkrMyUxOVaoFAPcasFUQAAAA"
       cite: RFC 3629 (UTF-8)
```

The base64 is also *technically* UTF-8, so that reading is offered too — at Low
confidence, ranked last. Nothing is hidden; everything is scored.

**[Full documentation →](https://securityronin.github.io/blob-decoder/)**

## What it recognises

| Kind | How | Confidence |
|---|---|---|
| binary plist, XML plist | `bplist00` magic / `<?xml…plist` + full `plist`-crate parse | High |
| gzip, zlib, Snappy | RFC 1952 / RFC 1950 header / Snappy framing magic, decompressed and unwrapped | High |
| JSON | object/array root, full `serde_json` parse | High |
| UUID / GUID | canonical hyphenated string | High |
| base64, hex | charset + structure, decoded and unwrapped | Medium if the payload is a concrete type, else Low |
| Protobuf (schemaless) | full schemaless wire-format decode via `protobuf-forensic-core` | Medium if the message carries a submessage/string, else Low (protobuf is a permissive, magic-less format) |
| UUID (raw 16 bytes), UTF-16LE, UTF-8 text | structural heuristic (a random blob could satisfy it) | Low |

Decoding is delegated to the mature crates that own each format — `plist`,
`base64`, `hex`, `uuid`, `flate2`, `snap`, `serde_json`, `protobuf-forensic-core`.
`blob-decoder` adds only the orchestration: **identify → dispatch → score →
recursively unwrap**.

## Install

```bash
cargo install blob-decoder
```

## Use as a library

```rust
use blob_decoder::{identify, BlobKind};

let gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00";
let cands = identify(gz);
assert_eq!(cands[0].kind, BlobKind::Gzip);
```

`identify` returns scored, best-first candidates; a wrapper candidate nests the
identification of its decoded payload, so you can walk the whole chain. Use
`identify_with_limits` to set the recursion depth and decompressed-size caps
explicitly.

## Safety

`blob-decoder` parses attacker-controllable bytes at a single entry point. It is
`#![forbid(unsafe_code)]`, panic-free (`clippy::unwrap_used`/`expect_used` denied
outside tests), fuzzed, and every decompression is size-capped and the recursion
depth-capped — a decompression bomb or infinitely-nested wrapper is bounded, not
fatal. See [Validation](https://securityronin.github.io/blob-decoder/validation/).

---

[Privacy Policy](https://securityronin.github.io/blob-decoder/privacy/) · [Terms of Service](https://securityronin.github.io/blob-decoder/terms/) · © 2026 Security Ronin Ltd
