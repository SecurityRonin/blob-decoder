# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/SecurityRonin/blob-decoder/compare/blob-decoder-v0.1.1...blob-decoder-v0.2.0) - 2026-07-29

### Added

- *(v8/blink)* GREEN — recursive V8/Blink value deserializer over real fixtures

## [0.1.1]

### Added

- Schemaless **Protobuf** detection: `BlobKind::Protobuf` decodes protobuf
  wire-format bytes (no `.proto`) via `protobuf-forensic-core` and reports the
  field structure. Scored conservatively — protobuf is a permissive, magic-less
  format, so a bare parse is Low; a message with a nested submessage or string
  lifts to Medium, and never above a magic-matched kind.

## [0.1.0]

### Added

- Initial `blob-decoder` library + `blob-decode` CLI: identify opaque blobs of
  unknown type, decode them, and report scored, cited candidates, recursively
  unwrapping nested wrappers (base64 → gzip → binary-plist).
- Recognises binary/XML plist, gzip, zlib, Snappy, JSON, UUID, base64, hex,
  UTF-16LE, and UTF-8 text, dispatching to `plist`/`flate2`/`snap`/`base64`/
  `hex`/`uuid`/`serde_json`.
- Bomb/DoS guards: size-capped decompression and depth-capped recursion via
  `Limits`; a `cargo-fuzz` `identify` target for the no-panic invariant.
