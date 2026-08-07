//! The orchestration engine: identify → dispatch → score → recursively unwrap.
//!
//! Every detector here is a thin dispatcher over a mature crate (`plist`,
//! `flate2`, `snap`, `base64`, `hex`, `uuid`, `serde_json`) — this module owns
//! only the *identification*, *scoring*, and *recursive unwrap*, never the codec
//! itself. All input is attacker-controllable, so the invariant is: no panic, no
//! OOM (every decompression is size-capped and the recursion is depth-capped),
//! and every failure degrades to a lower-confidence or absent reading.

use std::io::{Cursor, Read};

use base64::Engine as _;
use protobuf_forensic_core::{FieldValue, LenInterp};

use crate::{v8_value, BlobKind, Candidate, Confidence, DecodedChain, Limits};

/// Identify a blob with default [`Limits`]. Returns scored candidates, best
/// (highest [`Confidence`]) first. Always returns at least one candidate (an
/// [`BlobKind::Unknown`] reading that surfaces the raw head bytes when nothing
/// else matched).
#[must_use]
pub fn identify(bytes: &[u8]) -> Vec<Candidate> {
    identify_with_limits(bytes, Limits::default(), 0)
}

/// Identify a blob with explicit resource [`Limits`] and a starting recursion
/// `depth` — the entry point the recursive unwrap calls into.
#[must_use]
pub fn identify_with_limits(bytes: &[u8], limits: Limits, depth: usize) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();

    // Strong magic / full-parse detectors always run (cheap, high-signal).
    push(&mut out, detect_binary_plist(bytes));
    push(&mut out, detect_xml_plist(bytes));
    push(&mut out, detect_gzip(bytes, limits, depth));
    push(&mut out, detect_zlib(bytes, limits, depth));
    push(&mut out, detect_snappy(bytes, limits, depth));
    push(&mut out, detect_json(bytes));
    push(&mut out, detect_uuid_string(bytes));
    push(&mut out, detect_v8_blink(bytes));

    // Heuristic detectors are bounded by max_input (they scan / decode the whole
    // blob), so huge inputs get magic-only identification.
    if bytes.len() <= limits.max_input {
        push(&mut out, detect_base64(bytes, limits, depth));
        push(&mut out, detect_hex(bytes, limits, depth));
        push(&mut out, detect_uuid_bytes(bytes));
        push(&mut out, detect_utf16le(bytes));
        push(&mut out, detect_utf8_text(bytes));
        // Protobuf is a *permissive* wire format — many random/other-format byte
        // strings parse cleanly — so it runs last and is downgraded to Low when
        // any High-confidence kind already matched (it is never the true reading
        // of a gzip/plist/json blob).
        let strong = out.iter().any(|c| c.score == Confidence::High);
        push(&mut out, detect_protobuf(bytes, strong));
    }

    if out.is_empty() {
        out.push(unknown(bytes));
    }

    out.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| kind_rank(b.kind).cmp(&kind_rank(a.kind)))
            .then_with(|| a.kind.label().cmp(b.kind.label()))
    });
    out
}

fn push(out: &mut Vec<Candidate>, c: Option<Candidate>) {
    if let Some(c) = c {
        out.push(c);
    }
}

/// Specificity tiebreak when two candidates share a [`Confidence`]: a concrete
/// magic-identified type outranks a generic wrapper, which outranks bare text.
fn kind_rank(kind: BlobKind) -> u8 {
    match kind {
        BlobKind::BinaryPlist
        | BlobKind::XmlPlist
        | BlobKind::Gzip
        | BlobKind::Zlib
        | BlobKind::Snappy
        | BlobKind::Json
        | BlobKind::Uuid
        | BlobKind::V8Serialized
        | BlobKind::BlinkSerialized => 3,
        BlobKind::Base64 | BlobKind::Hex => 2,
        // Protobuf sits at the bottom heuristic tier with bare text: a successful
        // parse is a weak signal, so it never wins a confidence tie against a
        // magic-identified (rank-3) or decoded-wrapper (rank-2) kind.
        BlobKind::Protobuf | BlobKind::Utf16Le | BlobKind::Utf8Text => 1,
        BlobKind::Unknown => 0,
    }
}

// ---------------------------------------------------------------------------
// Wrapper payload recursion
// ---------------------------------------------------------------------------

/// Build the [`DecodedChain`] for a wrapper's decoded payload: recurse to
/// identify it, unless the depth cap is reached (the DoS backstop for
/// infinitely-nested wrappers).
fn build_chain(data: &[u8], capped: bool, limits: Limits, depth: usize) -> DecodedChain {
    let best = if depth + 1 >= limits.max_depth {
        Box::new(depth_capped(data))
    } else {
        identify_with_limits(data, limits, depth + 1)
            .into_iter()
            .next()
            // cov:unreachable: identify_with_limits never returns empty (pushes Unknown), kept defensive fallback.
            .map_or_else(|| Box::new(unknown(data)), Box::new)
    };
    DecodedChain {
        decoded_len: data.len(),
        capped,
        best,
    }
}

fn depth_capped(data: &[u8]) -> Candidate {
    Candidate {
        kind: BlobKind::Unknown,
        score: Confidence::Low,
        summary: format!(
            "recursion depth cap reached; {} bytes not further decoded (head: {})",
            data.len(),
            head_hex(data)
        ),
        citation: BlobKind::Unknown.citation(),
        inner: None,
    }
}

// ---------------------------------------------------------------------------
// Bounded decompression (the decompression-bomb guard)
// ---------------------------------------------------------------------------

/// Read at most `cap` bytes from `r`; return the bytes and whether the stream
/// was *capped* (had more to give). Bounds memory to `cap`, so a decompression
/// bomb can never exhaust it.
fn bounded_read<R: Read>(r: R, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    // take(cap+1): if we get cap+1 bytes the stream had more → it was capped.
    r.take(cap as u64 + 1).read_to_end(&mut out)?;
    let capped = out.len() > cap;
    if capped {
        out.truncate(cap);
    }
    Ok((out, capped))
}

// ---------------------------------------------------------------------------
// Detectors — strong magic / full parse
// ---------------------------------------------------------------------------

fn detect_binary_plist(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"bplist") {
        return None;
    }
    Some(match plist::Value::from_reader(Cursor::new(bytes)) {
        Ok(v) => leaf(
            BlobKind::BinaryPlist,
            Confidence::High,
            format!("binary plist: {}", describe_plist(&v)),
        ),
        Err(e) => leaf(
            BlobKind::BinaryPlist,
            Confidence::Medium,
            format!("bplist magic but parse failed: {e}"),
        ),
    })
}

fn detect_xml_plist(bytes: &[u8]) -> Option<Candidate> {
    let head = bytes.trim_ascii_start();
    // Bounded prefix scan for the plist markers, so a huge non-plist XML body is
    // rejected cheaply. Require the `plist` token to distinguish it from any XML.
    let probe = &head[..head.len().min(1024)];
    let starts_xml = probe.starts_with(b"<?xml")
        || probe.starts_with(b"<plist")
        || probe.starts_with(b"<!DOCTYPE");
    if !starts_xml || !contains(probe, b"plist") {
        return None;
    }
    Some(match plist::Value::from_reader(Cursor::new(bytes)) {
        Ok(v) => leaf(
            BlobKind::XmlPlist,
            Confidence::High,
            format!("XML plist: {}", describe_plist(&v)),
        ),
        Err(e) => leaf(
            BlobKind::XmlPlist,
            Confidence::Medium,
            format!("XML plist markup but parse failed: {e}"),
        ),
    })
}

fn detect_gzip(bytes: &[u8], limits: Limits, depth: usize) -> Option<Candidate> {
    // RFC 1952: magic 1f 8b. A 2-byte magic is specific enough that a decode
    // failure is still worth reporting (as a truncated/corrupt gzip).
    if !bytes.starts_with(&[0x1f, 0x8b]) {
        return None;
    }
    match bounded_read(flate2::read::GzDecoder::new(bytes), limits.max_output) {
        Ok((data, capped)) => Some(wrapper(
            BlobKind::Gzip,
            Confidence::High,
            format!(
                "gzip stream; {} bytes decompressed{}",
                data.len(),
                if capped { " (capped at limit)" } else { "" }
            ),
            build_chain(&data, capped, limits, depth),
        )),
        Err(e) => Some(leaf(
            BlobKind::Gzip,
            Confidence::Medium,
            format!("gzip magic but decompression failed: {e}"),
        )),
    }
}

fn detect_zlib(bytes: &[u8], limits: Limits, depth: usize) -> Option<Candidate> {
    // RFC 1950 header has no unique magic — only CM=deflate + the FCHECK mod-31
    // constraint (a weak ~1/500 filter). So we claim zlib ONLY on a SUCCESSFUL
    // decompress; a header match that fails to inflate is treated as coincidence
    // (returns None), never a false Medium on random bytes.
    if bytes.len() < 2 {
        return None;
    }
    let (cmf, flg) = (bytes[0], bytes[1]);
    if cmf & 0x0f != 0x08 || cmf >> 4 > 7 {
        return None;
    }
    if !((u16::from(cmf) << 8) | u16::from(flg)).is_multiple_of(31) {
        return None;
    }
    let (data, capped) =
        bounded_read(flate2::read::ZlibDecoder::new(bytes), limits.max_output).ok()?;
    Some(wrapper(
        BlobKind::Zlib,
        Confidence::High,
        format!(
            "zlib stream; {} bytes decompressed{}",
            data.len(),
            if capped { " (capped at limit)" } else { "" }
        ),
        build_chain(&data, capped, limits, depth),
    ))
}

fn detect_snappy(bytes: &[u8], limits: Limits, depth: usize) -> Option<Candidate> {
    // Snappy framing format: the stream identifier chunk (0xff + "sNaPpY").
    const MAGIC: &[u8] = &[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59];
    if !bytes.starts_with(MAGIC) {
        return None;
    }
    match bounded_read(snap::read::FrameDecoder::new(bytes), limits.max_output) {
        Ok((data, capped)) => Some(wrapper(
            BlobKind::Snappy,
            Confidence::High,
            format!(
                "Snappy framed stream; {} bytes decompressed{}",
                data.len(),
                if capped { " (capped at limit)" } else { "" }
            ),
            build_chain(&data, capped, limits, depth),
        )),
        Err(e) => Some(leaf(
            BlobKind::Snappy,
            Confidence::Medium,
            format!("Snappy magic but decompression failed: {e}"),
        )),
    }
}

fn detect_json(bytes: &[u8]) -> Option<Candidate> {
    let trimmed = bytes.trim_ascii();
    // Only object/array roots are claimed as JSON: a bare `123` or `true` is
    // technically JSON but too ambiguous to assert.
    if !matches!(trimmed.first(), Some(b'{' | b'[')) {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(trimmed).ok()?;
    Some(leaf(
        BlobKind::Json,
        Confidence::High,
        describe_json(&value),
    ))
}

fn detect_uuid_string(bytes: &[u8]) -> Option<Candidate> {
    let s = std::str::from_utf8(bytes).ok()?.trim();
    // Require the hyphenated (or braced/urn) canonical form: a bare 32-hex run is
    // better read as hex, so we do not claim it here.
    if !s.contains('-') {
        return None;
    }
    let u = uuid::Uuid::try_parse(s).ok()?;
    Some(leaf(
        BlobKind::Uuid,
        Confidence::High,
        format!(
            "UUID {u} (version {}, variant {:?})",
            u.get_version_num(),
            u.get_variant()
        ),
    ))
}

/// Detect a V8 structured-clone value or a Blink `SerializedScriptValue`. Both
/// open with the `0xFF` version tag; a Blink envelope is distinguished by a
/// framing byte (`0xFE` trailer or a nested `0xFF` V8 header) in the third
/// position, where a raw V8 stream carries a value tag instead.
///
/// A full decode is High confidence. A decode that fails *after* opening a valid
/// V8 value (e.g. a `kHostObject` typed array node serializes, or a truncated
/// stream) is Medium and fails loud — surfacing the tag — rather than fabricating
/// a reading. A `0xFF`-led blob whose first value tag is not a V8 tag is not
/// claimed at all (returns `None`).
fn detect_v8_blink(bytes: &[u8]) -> Option<Candidate> {
    if bytes.first() != Some(&0xFF) || bytes.len() < 3 {
        return None;
    }
    let is_blink = matches!(bytes.get(2), Some(0xFE | 0xFF));
    let (kind, result) = if is_blink {
        (
            BlobKind::BlinkSerialized,
            v8_value::deserialize_blink(bytes),
        )
    } else {
        (BlobKind::V8Serialized, v8_value::deserialize(bytes))
    };
    match result {
        Ok(v) => Some(leaf(
            kind,
            Confidence::High,
            format!("{}: {}", kind.label(), v.summary()),
        )),
        Err(e) => {
            // Only report a failed decode when the payload actually opened as V8
            // (a known value tag right after the version header) — otherwise a
            // random 0xFF-led binary would be mislabelled.
            let opens_as_v8 = bytes
                .get(1)
                .zip(bytes.get(2))
                .is_some_and(|(_ver, &t)| v8_value::is_value_tag(t) || t == 0xFE || t == 0xFF);
            if opens_as_v8 {
                Some(leaf(
                    kind,
                    Confidence::Medium,
                    format!("{} header but decode failed: {e}", kind.label()),
                ))
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Detectors — heuristic (coincidence-prone, scored Low unless the payload is
// itself recognised)
// ---------------------------------------------------------------------------

fn detect_base64(bytes: &[u8], limits: Limits, depth: usize) -> Option<Candidate> {
    let decoded = try_base64(bytes)?;
    let chain = build_chain(&decoded, false, limits, depth);
    let score = wrapper_score(chain.best.kind);
    Some(wrapper(
        BlobKind::Base64,
        score,
        format!("base64 text; decodes to {} bytes", chain.decoded_len),
        chain,
    ))
}

fn detect_hex(bytes: &[u8], limits: Limits, depth: usize) -> Option<Candidate> {
    let s = bytes.trim_ascii();
    if s.len() < 4 || !s.len().is_multiple_of(2) || !s.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let decoded = hex::decode(s).ok()?;
    let chain = build_chain(&decoded, false, limits, depth);
    let score = wrapper_score(chain.best.kind);
    Some(wrapper(
        BlobKind::Hex,
        score,
        format!("hexadecimal text; decodes to {} bytes", chain.decoded_len),
        chain,
    ))
}

fn detect_uuid_bytes(bytes: &[u8]) -> Option<Candidate> {
    let arr: [u8; 16] = bytes.try_into().ok()?;
    let u = uuid::Uuid::from_bytes(arr);
    Some(leaf(
        BlobKind::Uuid,
        // Any 16 bytes form a syntactically valid UUID — never over-claim.
        Confidence::Low,
        format!("if a UUID: {u} (note: any 16 bytes form a valid UUID)"),
    ))
}

fn detect_utf16le(bytes: &[u8]) -> Option<Candidate> {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let has_bom = bytes.starts_with(&[0xff, 0xfe]);
    let body = if has_bom { &bytes[2..] } else { bytes };
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if units.is_empty() {
        // The guard above establishes bytes.len() >= 4 and even, and `body` is
        // either `bytes` or `bytes[2..]` (BOM), so body.len() >= 2 and
        // chunks_exact(2) always yields at least one unit. Kept as a defensive
        // backstop in case the length guard above is ever relaxed.
        return None; // cov:unreachable: body.len() >= 2, so chunks_exact(2) yields >= 1 unit
    }
    let text = String::from_utf16(&units).ok()?;
    if !mostly_printable(&text) {
        return None;
    }
    // Without a BOM, require the ASCII-plane dominance that real UTF-16LE text
    // shows (high byte zero), else even-length binary would masquerade as text.
    let ascii_plane = body.chunks_exact(2).filter(|c| c[1] == 0).count();
    if !has_bom && (ascii_plane * 2) < units.len() {
        return None;
    }
    Some(leaf(
        BlobKind::Utf16Le,
        if has_bom {
            Confidence::Medium
        } else {
            Confidence::Low
        },
        format!("UTF-16LE text preview: \"{}\"", preview(&text)),
    ))
}

fn detect_utf8_text(bytes: &[u8]) -> Option<Candidate> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.is_empty() || !mostly_printable(s) {
        return None;
    }
    Some(leaf(
        BlobKind::Utf8Text,
        Confidence::Low,
        format!("UTF-8 text preview: \"{}\"", preview(s)),
    ))
}

/// Attempt a schemaless protobuf decode (delegated to `protobuf-forensic-core`).
/// A candidate is offered ONLY when the whole input decodes as a valid message
/// with ≥1 field — no trailing garbage, no empty message.
///
/// Scoring is deliberately conservative: protobuf is a *permissive* wire format
/// (a large fraction of arbitrary byte strings parse as "valid protobuf"), so a
/// bare successful parse is a WEAK signal and scores [`Confidence::Low`]. It is
/// lifted to [`Confidence::Medium`] only on a corroborating signal — the message
/// carries a nested submessage or a string field (structure a coincidental parse
/// rarely produces) AND no High-confidence kind already matched (`strong_present`),
/// so a gzip/plist/json blob that also happens to parse never gets a Medium.
fn detect_protobuf(bytes: &[u8], strong_present: bool) -> Option<Candidate> {
    let fields = protobuf_forensic_core::decode(bytes).ok()?;
    if fields.is_empty() {
        return None;
    }
    let (submessages, strings) = count_structure(&fields);
    let structured = submessages > 0 || strings > 0;
    let score = if structured && !strong_present {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    Some(leaf(
        BlobKind::Protobuf,
        score,
        format!(
            "protobuf wire-format message: {} field{} ({submessages} submessage{}, {strings} string{})",
            fields.len(),
            plural(fields.len()),
            plural(submessages),
            plural(strings),
        ),
    ))
}

/// Count the top-level length-delimited fields inferred as nested submessages and
/// as strings — the corroborating structure that distinguishes a plausibly-real
/// message from a coincidental parse of opaque scalars.
fn count_structure(fields: &[protobuf_forensic_core::Field]) -> (usize, usize) {
    let mut submessages = 0;
    let mut strings = 0;
    for f in fields {
        if let FieldValue::Len(lv) = &f.value {
            match lv.interp {
                LenInterp::Message(_) => submessages += 1,
                LenInterp::Text(_) => strings += 1,
                LenInterp::Bytes => {}
            }
        }
    }
    (submessages, strings)
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

// ---------------------------------------------------------------------------
// Scoring / construction helpers
// ---------------------------------------------------------------------------

/// A wrapper (base64/hex) whose decoded payload is itself a concrete recognised
/// type is Medium; one that decodes only to opaque bytes or plain text is Low
/// (the decode was probably coincidental).
fn wrapper_score(inner: BlobKind) -> Confidence {
    match inner {
        BlobKind::Unknown | BlobKind::Utf8Text | BlobKind::Utf16Le => Confidence::Low,
        _ => Confidence::Medium,
    }
}

fn leaf(kind: BlobKind, score: Confidence, summary: String) -> Candidate {
    Candidate {
        kind,
        score,
        summary,
        citation: kind.citation(),
        inner: None,
    }
}

fn wrapper(kind: BlobKind, score: Confidence, summary: String, chain: DecodedChain) -> Candidate {
    Candidate {
        kind,
        score,
        summary,
        citation: kind.citation(),
        inner: Some(Box::new(chain)),
    }
}

fn unknown(bytes: &[u8]) -> Candidate {
    Candidate {
        kind: BlobKind::Unknown,
        score: Confidence::Low,
        summary: if bytes.is_empty() {
            "unrecognized: empty input".to_owned()
        } else {
            format!(
                "unrecognized; {} bytes (head: {})",
                bytes.len(),
                head_hex(bytes)
            )
        },
        citation: BlobKind::Unknown.citation(),
        inner: None,
    }
}

/// Validate + decode base64 (standard or URL-safe, whitespace-tolerant). Returns
/// the decoded bytes, or `None` if the input is not clean, correctly-padded
/// base64 — delegating the decode itself to the `base64` crate.
fn try_base64(bytes: &[u8]) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if cleaned.len() < 8 || !cleaned.len().is_multiple_of(4) {
        return None;
    }
    let eq = cleaned
        .iter()
        .position(|&b| b == b'=')
        .unwrap_or(cleaned.len());
    let (body, padding) = cleaned.split_at(eq);
    if padding.len() > 2 || padding.iter().any(|&b| b != b'=') || body.is_empty() {
        return None;
    }
    let is_std = body
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    let is_url = body
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if is_std {
        base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .ok()
    } else if is_url {
        base64::engine::general_purpose::URL_SAFE
            .decode(&cleaned)
            .ok()
    } else {
        None
    }
}

fn describe_plist(v: &plist::Value) -> String {
    match v {
        plist::Value::Array(a) => format!("array with {} items", a.len()),
        plist::Value::Dictionary(d) => format!("dict with {} entries", d.len()),
        plist::Value::Boolean(_) => "boolean".to_owned(),
        plist::Value::Data(d) => format!("data ({} bytes)", d.len()),
        plist::Value::Date(_) => "date".to_owned(),
        plist::Value::Real(_) => "real".to_owned(),
        plist::Value::Integer(_) => "integer".to_owned(),
        plist::Value::String(_) => "string".to_owned(),
        plist::Value::Uid(_) => "uid".to_owned(),
        // `plist::Value` (plist 1.9.0) has exactly the nine variants matched
        // above — Array, Dictionary, Boolean, Data, Date, Real, Integer, String,
        // Uid. The enum is `#[non_exhaustive]`, so this arm exists only so a
        // future plist release that adds a variant still compiles here.
        _ => "value".to_owned(), // cov:unreachable: plist 1.9.0 has only the nine variants above
    }
}

fn describe_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => format!("JSON object with {} keys", m.len()),
        serde_json::Value::Array(a) => format!("JSON array with {} elements", a.len()),
        // Unreachable: detect_json only enters on `{`/`[` roots.
        _ => "JSON value".to_owned(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn mostly_printable(s: &str) -> bool {
    let total = s.chars().count();
    if total == 0 {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        .count();
    (printable * 100) >= (total * 90)
}

fn head_hex(bytes: &[u8]) -> String {
    let n = bytes.len().min(16);
    let mut s = hex::encode(&bytes[..n]);
    if bytes.len() > n {
        s = format!("{s} (+{} more)", bytes.len() - n);
    }
    s
}

fn preview(s: &str) -> String {
    const MAX: usize = 48;
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() <= MAX {
        flat
    } else {
        let cut: String = flat.chars().take(MAX).collect();
        format!("{cut}… ({} chars total)", s.chars().count())
    }
}

/// Unit tests for the module-private helpers whose defensive arms the public
/// `identify` path cannot reach (they are dominated by an earlier guard), so the
/// behaviour is pinned here rather than assumed.
#[cfg(test)]
mod tests {
    use super::{describe_json, detect_protobuf, kind_rank, mostly_printable};
    use crate::{BlobKind, Confidence};

    /// `Unknown` must rank below every other kind so an unrecognized reading always
    /// sorts last when it ties on confidence. The public path never places an
    /// `Unknown` candidate alongside others (it is pushed only when nothing else
    /// matched, giving a one-element list that `sort_by` never compares), so the
    /// ordering contract is asserted directly here.
    #[test]
    fn unknown_ranks_below_every_other_kind() {
        let unknown = kind_rank(BlobKind::Unknown);
        assert_eq!(unknown, 0);
        for kind in [
            BlobKind::BinaryPlist,
            BlobKind::XmlPlist,
            BlobKind::Gzip,
            BlobKind::Zlib,
            BlobKind::Snappy,
            BlobKind::Base64,
            BlobKind::Hex,
            BlobKind::Uuid,
            BlobKind::Json,
            BlobKind::Protobuf,
            BlobKind::V8Serialized,
            BlobKind::BlinkSerialized,
            BlobKind::Utf16Le,
            BlobKind::Utf8Text,
        ] {
            let rank = kind_rank(kind);
            assert!(rank > unknown, "{kind:?} must outrank Unknown, got {rank}");
        }
    }

    /// `describe_json` is only called on `{`/`[` roots, so its fallback arm is a
    /// defensive backstop. It must still describe a scalar root honestly rather than
    /// claiming a shape it does not have.
    #[test]
    fn describe_json_falls_back_for_a_scalar_root() {
        assert_eq!(
            describe_json(&serde_json::Value::Object(serde_json::Map::new())),
            "JSON object with 0 keys"
        );
        assert_eq!(
            describe_json(&serde_json::Value::Array(vec![serde_json::Value::Null])),
            "JSON array with 1 elements"
        );
        for scalar in [
            serde_json::Value::Null,
            serde_json::Value::Bool(true),
            serde_json::Value::from(1),
            serde_json::Value::from("s"),
        ] {
            assert_eq!(describe_json(&scalar), "JSON value");
        }
    }

    /// Empty text is not "mostly printable": a zero-length decode is no evidence of
    /// text at all. Both callers short-circuit on empty before asking, so the
    /// contract is pinned here.
    #[test]
    fn mostly_printable_rejects_empty_text() {
        assert!(!mostly_printable(""));
        assert!(mostly_printable("hello"));
        assert!(mostly_printable("tab\tnewline\r\n"));
        // 2 printable of 12 chars is far below the 90% floor.
        assert!(!mostly_printable("ab\0\0\0\0\0\0\0\0\0\0"));
    }

    /// A protobuf message whose length-delimited fields carry *corroborating
    /// structure* — one nested submessage and one string. Opaque scalars alone
    /// could be a coincidental parse of any byte run, so only this structured
    /// shape earns `Medium`, and only when no stronger reading is competing.
    ///
    /// Wire format, hand-assembled so the fixture is readable:
    ///   `0A 05 "hello"`  field 1, LEN, five text bytes  -> a string
    ///   `12 02 08 01`    field 2, LEN, holding `08 01`  -> a nested message
    ///                    (`08 01` is field 1, varint, value 1)
    const STRUCTURED: &[u8] = b"\x0a\x05hello\x12\x02\x08\x01";

    #[test]
    fn structured_protobuf_scores_medium_only_without_a_stronger_reading() {
        let c = detect_protobuf(STRUCTURED, false).expect("two well-formed fields decode");
        assert_eq!(c.kind, BlobKind::Protobuf);
        assert_eq!(
            c.score,
            Confidence::Medium,
            "submessage + string is corroborating structure: {}",
            c.summary
        );
        assert!(
            c.summary.contains("1 submessage") && c.summary.contains("1 string"),
            "both field shapes should be counted and reported: {}",
            c.summary
        );
    }

    #[test]
    fn the_same_bytes_score_low_when_a_stronger_reading_is_present() {
        // Identical input, `strong_present = true`: the structure is unchanged,
        // so anything but a downgrade would mean the flag is not consulted.
        let c = detect_protobuf(STRUCTURED, true).expect("two well-formed fields decode");
        assert_eq!(c.score, Confidence::Low);
    }
}
