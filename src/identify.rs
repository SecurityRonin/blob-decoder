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

use crate::{BlobKind, Candidate, Confidence, DecodedChain, Limits};

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

    // Heuristic detectors are bounded by max_input (they scan / decode the whole
    // blob), so huge inputs get magic-only identification.
    if bytes.len() <= limits.max_input {
        push(&mut out, detect_base64(bytes, limits, depth));
        push(&mut out, detect_hex(bytes, limits, depth));
        push(&mut out, detect_uuid_bytes(bytes));
        push(&mut out, detect_utf16le(bytes));
        push(&mut out, detect_utf8_text(bytes));
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
        | BlobKind::Uuid => 3,
        BlobKind::Base64 | BlobKind::Hex => 2,
        BlobKind::Utf16Le | BlobKind::Utf8Text => 1,
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
        return None;
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
        _ => "value".to_owned(),
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
