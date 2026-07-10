# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial `blob-decoder` library + `blob-decode` CLI: identify opaque blobs of
  unknown type, decode them, and report scored, cited candidates, recursively
  unwrapping nested wrappers (base64 → gzip → binary-plist).
- Recognises binary/XML plist, gzip, zlib, Snappy, JSON, UUID, base64, hex,
  UTF-16LE, and UTF-8 text, dispatching to `plist`/`flate2`/`snap`/`base64`/
  `hex`/`uuid`/`serde_json`.
- Bomb/DoS guards: size-capped decompression and depth-capped recursion via
  `Limits`; a `cargo-fuzz` `identify` target for the no-panic invariant.
