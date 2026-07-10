//! `blob-decoder` — identify and decode opaque forensic blobs of unknown type.
//!
//! Hand it raw bytes; it reports what they are, decodes them, and returns
//! **scored, cited candidates** — recursively unwrapping nested wrappers (a
//! base64'd, gzip'd binary-plist is reported as the full
//! `Base64 → Gzip → BinaryPlist` chain).
//!
//! The actual decoding is delegated to mature crates (`plist`, `base64`, `hex`,
//! `uuid`, `flate2`, `snap`, `serde_json`); this crate adds only the
//! orchestration layer: identify → dispatch → score → recursively unwrap, plus a
//! clean forensic result type.
#![forbid(unsafe_code)]
