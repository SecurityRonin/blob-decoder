# blob-decoder — Product Requirements

*A reverse-written product doc grounded in a same-session read of `src/`, `README.md`,
`Cargo.toml`, `docs/validation.md`, and the git history (2026-07-24). The load-bearing
decisions live as ADRs [0001](decisions/0001-single-crate-engine-plus-humble-cli.md)–[0008](decisions/0008-schemaless-protobuf-via-fleet-crate-scored-conservatively.md)
under [`docs/decisions/`](decisions/). Everything described below is shipped behavior
(v0.1.1) unless explicitly marked as future work.*

## Executive Summary

Every examination turns up an opaque value — a database column full of gibberish, a
property-list `Data` field, a config string that is obviously encoded but of unknown
kind. **blob-decoder hands the analyst back what those bytes are: it identifies the
type, decodes it, and recursively unwraps nested wrappers**, so a base64'd, gzip'd
binary-plist comes back as the whole `Base64 → Gzip → BinaryPlist` chain, each link
scored and cited to its authoritative spec.

It never guesses one answer for an ambiguous blob. It returns **every plausible reading,
ranked by honest confidence** — the base64 that is *also* technically UTF-8 is offered
too, at Low confidence, ranked last. Nothing is hidden; everything is scored.

Two surfaces, one engine:

- **`blob-decode`** — the analyst CLI. `blob-decode --string "$b64"` (or a file, stdin,
  `--hex`, `--base64`) prints the scored candidate tree; `--json` emits it for a
  pipeline; exit codes are pipeline-safe (`0` identified, `2` nothing matched, `1` input
  error).
- **`blob_decoder`** — the importable library other fleet analysis crates link to decode
  BLOBs inline (a SQLite value, a plist field), always compiled in, never behind a
  feature flag.

The crate writes no codec of its own: decoding is delegated to the mature crates that
own each format (`plist`, `flate2`, `snap`, `base64`, `hex`, `uuid`, `serde_json`,
`protobuf-forensic-core`). Its value is the orchestration none of them provides —
**identify → dispatch → score → recursively unwrap** ([ADR 0002](decisions/0002-delegate-decoding-to-mature-crates.md)).

## 1. Problem and users

**The pain.** A forensic analyst constantly meets bytes whose type is unknown or only
half-known. The value in an evidence column is base64; decoding it by hand yields more
opaque bytes that turn out to be gzip; decompressing *those* yields a binary plist. Each
step is a manual `base64 -d | gunzip | plutil -p` guess, and the analyst has to *know*
each layer to strip it. When the encoding is ambiguous (hex vs base64, raw-16-bytes vs
UUID), a single-answer tool guesses — and a confident wrong guess costs more than no
answer.

**Primary users.**

- **The forensic analyst / examiner** running `blob-decode` on an opaque value during
  triage or deep-dive, who needs the type, the decoded content, and a citation they can
  put in a report — with the ambiguity made explicit, not hidden.
- **Fleet analysis crates** (the `*-forensic` / analysis layer) that link the
  `blob_decoder` engine to decode BLOB/`Data` fields inline while parsing an artifact,
  so an opaque SQLite value surfaces as "binary plist → {…}" from the zero-config path
  rather than as raw bytes.

## 2. What it does

Given raw bytes, `identify(&[u8]) -> Vec<Candidate>` returns scored candidate readings,
best (highest `Confidence`) first, always at least one (an `Unknown` reading that
surfaces the raw head bytes when nothing matched). Each `Candidate` carries:

- **`kind`** — the recognised `BlobKind`;
- **`score`** — `Low < Medium < High`, reflecting the *strength of the check*, not a
  wish ([ADR 0003](decisions/0003-non-exclusive-scored-cited-candidates.md));
- **`citation`** — the authoritative spec the kind was matched against (RFC 4648,
  RFC 1952, RFC 9562, Apple `CFBinaryPList`, …);
- **`summary`** — what was found (root type, byte counts, decoded-text preview, or the
  raw head bytes for `Unknown`);
- **`inner`** — for a *wrapper* kind (gzip/zlib/Snappy/base64/hex), the nested
  identification of the decoded payload: the next link in the chain
  ([ADR 0004](decisions/0004-recursive-unwrap-with-bounded-caps.md)).

The CLI renders that tree for the eye (indented, `HIGH`/`MED`/`LOW`, `cite:` lines) or
faithfully as JSON for a pipe.

## 3. Scope — what it recognises

| Kind | How | Confidence |
|---|---|---|
| binary plist, XML plist | `bplist00` magic / `<?xml…plist` markers + full `plist`-crate parse | High (parsed) / Medium (magic but parse failed) |
| gzip, zlib, Snappy | RFC 1952 / RFC 1950 header / Snappy framing magic, decompressed and unwrapped | High (decompressed) |
| JSON | object/array root, full `serde_json` parse | High |
| UUID / GUID (string) | canonical hyphenated / braced / urn form | High |
| base64, hex | charset + structure, decoded and unwrapped | Medium if the payload is a concrete type, else Low |
| Protobuf (schemaless) | full wire-format decode via `protobuf-forensic-core` | Low by default; Medium only on corroborating structure, never above a magic kind ([ADR 0008](decisions/0008-schemaless-protobuf-via-fleet-crate-scored-conservatively.md)) |
| UUID (raw 16 bytes), UTF-16LE, UTF-8 text | structural heuristic (a random blob could satisfy it) | Low (Medium for BOM'd UTF-16LE) |
| Unknown | nothing matched — raw head bytes reported | Low |

Input sources for the CLI: a file, stdin (`-` or omitted), or inline `--string` /
`--hex` / `--base64`. Output: human tree (default) or `--json`, optionally `--top N`.

## 4. Non-goals

- **Writing any codec.** Every decode is delegated to the crate that owns the format
  ([ADR 0002](decisions/0002-delegate-decoding-to-mature-crates.md)); blob-decoder adds
  only identification, scoring, and recursion.
- **Asserting a single verdict for an ambiguous blob.** The output is a ranked set, never
  one forced answer ([ADR 0003](decisions/0003-non-exclusive-scored-cited-candidates.md)).
- **Schema-driven protobuf.** Decoding is schemaless (no `.proto`); field structure is
  inferred, not resolved against a message definition.
- **Unbounded decode.** Decompression is size-capped and recursion depth-capped; a bomb
  or an infinitely-nested wrapper is bounded, not fatal
  ([ADR 0004](decisions/0004-recursive-unwrap-with-bounded-caps.md)) — the tool never
  becomes the attack.
- **A `-core` / `-forensic` split.** One crate; there is no lean-vs-heavy library
  consumer or raw-layout auditor to serve ([ADR 0001](decisions/0001-single-crate-engine-plus-humble-cli.md)).
- **Encoding / re-wrapping bytes.** This is a read/identify tool, not an encoder.

## 5. Requirements

- **R1 — Identify, don't guess.** Return every plausible reading, ranked by a confidence
  that reflects the strength of the check; a Low reading lowers rank, never hides.
- **R2 — Cite every reading.** Each candidate names the authoritative spec it matched, so
  a finding is traceable, not asserted.
- **R3 — Unwrap the whole chain.** A wrapper reports the identification of its decoded
  payload, recursively, so nested encodings resolve to their innermost type.
- **R4 — Never panic, never OOM on untrusted input.** `forbid(unsafe)`, panic-free lints,
  size-capped decompression, depth-capped recursion, and a `cargo-fuzz` target on the one
  entry point ([ADR 0005](decisions/0005-paranoid-gatekeeper-panic-free-fuzzed.md)).
- **R5 — Capable by default.** The CLI ships by default; no format is behind a feature
  flag. A library consumer opts into a lean build with `default-features = false`
  ([ADR 0006](decisions/0006-capable-by-default-cli-lean-library-optout.md)).
- **R6 — Pipeline-safe CLI.** Faithful `--json` output; exit codes `0`/`2`/`1` for
  identified / nothing-matched / input-error.
- **R7 — Honest MSRV.** The declared floor (`1.88.0`) is the dependency graph's true
  minimum, CI-verified ([ADR 0007](decisions/0007-msrv-floor-1-88-driven-by-plist.md)).

## 6. Validation approach

The crate decodes nothing itself, so validation targets what it *adds* — identification,
scoring, and recursive unwrap — and is documented in
[`docs/validation.md`](validation.md):

- **Tier 2 (real inputs, independent producer):** identification/decode tests feed inputs
  produced by tools *other than* the decoder crate under test — CPython `plistlib`, system
  `gzip`/`base64`, `uuidgen`, `protoc --encode` — then assert the reading and the recovered
  payload. A wrong decode cannot pass by agreeing with a fixture we hand-encoded. These
  skip cleanly when a producer tool is absent (`tests/magic.rs`, `tests/nested.rs`,
  `tests/identifiers.rs`, `tests/protobuf.rs`).
- **Tier 3 (committed structural + adversarial fixtures):** small self-produced plist
  fixtures keep those paths exercised everywhere; `tests/robustness.rs` and the fuzz
  target assert the untrusted-input invariants (no panic, bounded memory on a 64 MiB-of-
  zeros zlib bomb, deeply-nested wrappers stopped at the depth cap, random bytes degrading
  to Low/Unknown).

## 7. Future work

- A `-core` split, *if and when* a third-party consumer needs a lean subset (deferred
  under YAGNI — [ADR 0001](decisions/0001-single-crate-engine-plus-humble-cli.md)).
- Additional formats follow the same pattern: add the owning crate plus one dispatcher and
  one `BlobKind` variant; no new parser.
