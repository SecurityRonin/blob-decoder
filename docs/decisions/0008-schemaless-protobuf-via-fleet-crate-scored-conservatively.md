# 8. Schemaless Protobuf via the fleet's protobuf-forensic-core, scored conservatively

Date: 2026-07-24
Status: Accepted

## Context

Protocol Buffers wire data turns up constantly in forensic blobs, but it has **no
magic number** and a *permissive* grammar: a large fraction of random or other-format
byte strings decode cleanly as "valid protobuf" (the same reason `protoc --decode_raw`
succeeds on so much junk). Adding it naively would flood every ambiguous blob with a
confident false "this is protobuf" reading — the opposite of the honest-scoring
posture in ADR 3. Protobuf detection was added after the initial release
(commits `fc7b766` RED / `87407ad` GREEN, shipped in 0.1.1 per `CHANGELOG.md`).

## Decision

- **Decode with the fleet's own crate.** `detect_protobuf` delegates to
  `protobuf-forensic-core` (`Cargo.toml`: *"schemaless protobuf wire decoder,
  zero-dep, MSRV 1.80"*), honoring the "prefer our own crates" rule rather than pulling
  a third-party schemaless decoder.
- **Offer a candidate only on a clean, non-empty decode** — the whole input parses as a
  message with ≥1 field, no trailing garbage, no empty message.
- **Score conservatively, because a bare parse is a weak signal** (`src/identify.rs`,
  `detect_protobuf`, and `docs/validation.md`):
  - **Low** by default — a valid message of only opaque scalars/bytes is exactly the
    coincidental case;
  - **Medium** only on a corroborating structure a chance parse rarely produces (a
    nested submessage or a string field, counted by `count_structure`) **and** only
    when no High-confidence kind already matched (`strong_present`), so a gzip/plist/JSON
    blob that also happens to parse never claims a protobuf Medium;
  - **never High**, and its `kind_rank` sits at the bottom heuristic tier, so it never
    outranks a magic-identified or decoded-wrapper kind on a confidence tie.
- **Run it last**, after the strong detectors, so `strong_present` is known.

## Consequences

- Protobuf is recognised and its field structure described, without polluting
  ambiguous results with false confidence — a lone varint reads Low, a structured
  message reads Medium at most.
- The dependency on `protobuf-forensic-core` keeps the schemaless decoder inside the
  fleet, cross-checked by its own tests, and is validated here against independent
  `protoc --encode` output (`tests/protobuf.rs`, `docs/validation.md`).
- The permissive-format handling is a concrete instance of the ADR-3 epistemics: rank
  by strength of check, never assert.
