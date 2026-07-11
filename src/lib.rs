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
//!
//! # Epistemics
//!
//! A blob is often underdetermined: bytes that are valid hex are frequently also
//! valid base64, and a run of ASCII is *technically* decodable as base64 to
//! gibberish. `blob-decoder` never asserts a single verdict — it returns every
//! plausible reading with an honest [`Confidence`], and a low-confidence reading
//! lowers the rank, never hides the finding.
//!
//! # Example
//!
//! ```
//! // gzip magic (0x1f 0x8b) → identified as a Gzip wrapper.
//! let gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00";
//! let cands = blob_decoder::identify(gz);
//! assert_eq!(cands[0].kind, blob_decoder::BlobKind::Gzip);
//! ```
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod identify;

pub use identify::{identify, identify_with_limits};

/// The engine's version (`CARGO_PKG_VERSION`), for callers that surface it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A recognised (or unrecognised) blob type.
///
/// The `citation` and `label` are carried per-kind so a reading is traceable to
/// the authoritative format definition it was matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobKind {
    /// Apple binary property list (`bplist00` magic).
    BinaryPlist,
    /// Apple XML property list.
    XmlPlist,
    /// gzip member (`1f 8b` magic).
    Gzip,
    /// zlib stream (RFC 1950 header).
    Zlib,
    /// Snappy framed stream.
    Snappy,
    /// base64 text (standard or URL-safe alphabet).
    Base64,
    /// Hexadecimal text.
    Hex,
    /// A UUID / GUID (16 raw bytes or the canonical hyphenated string).
    Uuid,
    /// JSON (object or array root).
    Json,
    /// Protocol Buffers wire-format message (schemaless / no `.proto`).
    Protobuf,
    /// UTF-16LE text.
    Utf16Le,
    /// UTF-8 text (printable).
    Utf8Text,
    /// No known type matched — the raw head bytes are reported for the analyst.
    Unknown,
}

impl BlobKind {
    /// A short human label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::BinaryPlist => "Apple binary property list",
            Self::XmlPlist => "Apple XML property list",
            Self::Gzip => "gzip stream",
            Self::Zlib => "zlib stream",
            Self::Snappy => "Snappy framed stream",
            Self::Base64 => "base64 text",
            Self::Hex => "hexadecimal text",
            Self::Uuid => "UUID / GUID",
            Self::Json => "JSON",
            Self::Protobuf => "Protocol Buffers (schemaless)",
            Self::Utf16Le => "UTF-16LE text",
            Self::Utf8Text => "UTF-8 text",
            Self::Unknown => "unknown",
        }
    }

    /// The authoritative spec / reference this kind is matched against.
    #[must_use]
    pub fn citation(self) -> &'static str {
        match self {
            Self::BinaryPlist | Self::XmlPlist => {
                "Apple CoreFoundation CFBinaryPList.c; `man 5 plist`"
            }
            Self::Gzip => "RFC 1952 (GZIP file format)",
            Self::Zlib => "RFC 1950 (ZLIB compressed data format)",
            Self::Snappy => "google/snappy framing_format.txt",
            Self::Base64 => "RFC 4648 §4-5 (Base 64 / Base64url)",
            Self::Hex => "RFC 4648 §8 (Base 16)",
            Self::Uuid => "RFC 9562 (UUID)",
            Self::Json => "RFC 8259 (JSON)",
            Self::Protobuf => "protobuf.dev encoding spec (wire format)",
            Self::Utf16Le => "The Unicode Standard; RFC 2781 (UTF-16LE)",
            Self::Utf8Text => "RFC 3629 (UTF-8)",
            Self::Unknown => "no matching format",
        }
    }

    /// True when this kind is a *wrapper* whose payload is itself another blob
    /// (base64/hex text, or a compression stream) — the recursion drivers.
    #[must_use]
    pub fn is_wrapper(self) -> bool {
        matches!(
            self,
            Self::Gzip | Self::Zlib | Self::Snappy | Self::Base64 | Self::Hex
        )
    }
}

/// How strongly the evidence supports a reading. Ordered `Low < Medium < High`
/// so candidates sort best-first by *descending* confidence.
///
/// - [`Confidence::High`] — a strong, near-unique MAGIC signature or a full
///   successful structural parse (`bplist00`, `1f 8b`, a valid RFC 1950 header,
///   a parseable JSON object, a canonical hyphenated UUID string).
/// - [`Confidence::Medium`] — a magic matched but the payload failed to fully
///   decode, or a heuristic wrapper (base64/hex) whose decoded payload was
///   itself recognised as a concrete type.
/// - [`Confidence::Low`] — a purely structural heuristic that a random blob
///   could satisfy by coincidence (16 arbitrary bytes as a UUID; base64/hex text
///   decoding only to more opaque bytes; plain printable text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A coincidence-prone structural heuristic.
    Low,
    /// A magic matched but payload decode was partial, or a heuristic wrapper
    /// whose payload was recognised.
    Medium,
    /// A strong magic signature or a full successful parse.
    High,
}

/// One scored, cited candidate reading of a blob. A wrapper candidate nests the
/// identification of its decoded payload in [`Candidate::inner`], so a
/// `base64 → gzip → binary-plist` blob reports the whole chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Candidate {
    /// The identified (or unidentified) kind.
    pub kind: BlobKind,
    /// How strongly the evidence supports this reading.
    pub score: Confidence,
    /// A human summary of *what was found* (root type, byte counts, decoded
    /// text prefix, or — for [`BlobKind::Unknown`] — the raw head bytes).
    pub summary: String,
    /// The authoritative spec citation for [`Candidate::kind`].
    pub citation: &'static str,
    /// For a wrapper kind, the identification of the decoded/decompressed
    /// payload — the next link in the chain. `None` for a leaf reading, a failed
    /// decode, or when the recursion depth cap was reached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner: Option<Box<DecodedChain>>,
}

/// The decoded payload of a wrapper [`Candidate`]: how many bytes it produced
/// and the best reading of those bytes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecodedChain {
    /// Number of bytes the wrapper decoded/decompressed to (after any cap).
    pub decoded_len: usize,
    /// True when the decoded output was truncated at the size cap (a possible
    /// decompression bomb) — the payload reading is of the capped prefix.
    pub capped: bool,
    /// The best (highest-confidence) reading of the decoded payload.
    pub best: Box<Candidate>,
}

/// Resource bounds for [`identify_with_limits`] — the guard against
/// decompression bombs and infinitely-nested wrappers on untrusted input.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum recursion depth through nested wrappers.
    pub max_depth: usize,
    /// Maximum bytes to hold from a single decompression/decode step (a
    /// decompression bomb is capped here, never allowed to exhaust memory).
    pub max_output: usize,
    /// Inputs larger than this skip the *heuristic* decoders (base64/hex/text);
    /// magic-signature detection still runs. Bounds worst-case work.
    pub max_input: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_output: 64 * 1024 * 1024,
            max_input: 128 * 1024 * 1024,
        }
    }
}
