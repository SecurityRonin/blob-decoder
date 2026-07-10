//! `blob-decode` CLI — a thin Humble-Object shell over the `blob-decoder` engine.
//!
//! Hand it a blob (from a file, stdin, or inline as `--string`/`--hex`/
//! `--base64`) and it prints the scored, cited candidate readings, recursively
//! unwrapping any nested wrappers. Exit codes are pipeline-safe: `0` a concrete
//! type was identified, `2` nothing matched (Unknown), `1` an input error.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::Read;
use std::process::ExitCode;

use base64::Engine as _;
use blob_decoder::{identify, BlobKind, Candidate, Confidence};
use clap::Parser;

/// Identify and decode opaque blobs of unknown type.
#[derive(Parser, Debug)]
#[command(
    name = "blob-decode",
    version,
    about = "Identify and decode opaque blobs of unknown type — scored, cited candidates."
)]
struct Cli {
    /// File to read the blob from ('-' or omitted reads stdin).
    file: Option<String>,
    /// Treat this literal string's UTF-8 bytes as the blob.
    #[arg(long, conflicts_with_all = ["hex", "base64", "file"])]
    string: Option<String>,
    /// Decode this hex string into the blob's bytes.
    #[arg(long, conflicts_with_all = ["string", "base64", "file"])]
    hex: Option<String>,
    /// Decode this base64 string into the blob's bytes.
    #[arg(long = "base64", conflicts_with_all = ["string", "hex", "file"])]
    base64: Option<String>,
    /// Emit JSON instead of the human-readable tree.
    #[arg(long)]
    json: bool,
    /// Show at most N readings (default: all).
    #[arg(long, value_name = "N")]
    top: Option<usize>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let bytes = match load(&cli) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("blob-decode: {e}");
            return ExitCode::from(1);
        }
    };

    let mut cands = identify(&bytes);
    if let Some(n) = cli.top {
        cands.truncate(n);
    }

    if cli.json {
        match serde_json::to_string_pretty(&cands) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("blob-decode: serialization failed: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        print_human(&bytes, &cands);
    }

    // Pipeline signal: 2 when nothing concrete was identified (best is Unknown).
    if cands.first().is_none_or(|c| c.kind == BlobKind::Unknown) {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// Resolve the blob bytes from whichever input source was given.
fn load(cli: &Cli) -> Result<Vec<u8>, String> {
    if let Some(s) = &cli.string {
        return Ok(s.clone().into_bytes());
    }
    if let Some(h) = &cli.hex {
        return hex::decode(h.trim()).map_err(|e| format!("invalid hex input: {e}"));
    }
    if let Some(b) = &cli.base64 {
        return base64::engine::general_purpose::STANDARD
            .decode(b.trim())
            .map_err(|e| format!("invalid base64 input: {e}"));
    }
    match cli.file.as_deref() {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("reading stdin: {e}"))?;
            Ok(buf)
        }
        Some(path) => std::fs::read(path).map_err(|e| format!("{path}: {e}")),
    }
}

fn print_human(bytes: &[u8], cands: &[Candidate]) {
    println!(
        "blob-decode: {} bytes; {} candidate reading(s), best first:",
        bytes.len(),
        cands.len()
    );
    for c in cands {
        print_candidate(c, 1);
    }
}

fn print_candidate(c: &Candidate, indent: usize) {
    let pad = "  ".repeat(indent);
    println!(
        "{pad}[{}] {} — {}",
        conf_str(c.score),
        c.kind.label(),
        c.summary
    );
    println!("{pad}     cite: {}", c.citation);
    if let Some(chain) = &c.inner {
        println!(
            "{pad}     decodes to {} bytes{}:",
            chain.decoded_len,
            if chain.capped { " (capped)" } else { "" }
        );
        print_candidate(&chain.best, indent + 1);
    }
}

fn conf_str(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "HIGH",
        Confidence::Medium => "MED ",
        Confidence::Low => "LOW ",
    }
}
