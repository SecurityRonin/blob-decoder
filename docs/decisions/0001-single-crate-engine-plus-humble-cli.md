# 1. Single crate: an engine library plus a Humble-Object CLI, no core/forensic split

Date: 2026-07-24
Status: Accepted

## Context

The fleet's default crate shape is the reader/analyzer split — a lean `<x>-core`
library and a heavier `<x>-forensic` analyzer, or a lean `<x>-core` plus a
batteries-included `<x>` binary (blazehash → blazehash-core). That split exists to
serve two different consumers: a third-party library that wants only the lean
primitives, and a binary that wants everything compiled in.

blob-decoder has no such divergence. Its whole value is one orchestration layer
(identify → dispatch → score → recursively unwrap); there is no lean-vs-heavy
subset a downstream library would want to link separately, and no format-reader
whose raw byte layout an auditor must reach beneath. The identification engine and
the CLI over it are the same body of work.

## Decision

Ship **one crate**, `blob-decoder`, exposing:

- a **library** (`src/lib.rs` + `src/identify.rs`, `[lib] name = "blob_decoder"`) —
  the importable, fully testable engine (`identify`, `identify_with_limits`, the
  `Candidate`/`DecodedChain`/`BlobKind`/`Confidence`/`Limits` types); and
- a **thin CLI shell** (`src/main.rs`, `[[bin]] name = "blob-decode"`) that is a
  Humble Object — every decision lives in the library; `main.rs` only loads bytes
  from a source, calls `identify`, and prints. The Cargo.toml records this verbatim:
  *"One crate: a library … plus a thin CLI shell over it (Humble Object). No `-core`
  split: there is no lean-vs-heavy library consumer to serve."*

## Consequences

- The library is testable end-to-end without the binary; the CLI carries no logic to
  test beyond input-source resolution and output formatting (`tests/cli.rs`).
- Coverage gates on the library engine (`scripts/coverage-gate.py`), and the CLI stays
  thin enough that the Humble-Object boundary holds.
- If a future third-party consumer ever needs a lean subset, a `-core` split can be
  carved out then — deferred under YAGNI rather than pre-built.
