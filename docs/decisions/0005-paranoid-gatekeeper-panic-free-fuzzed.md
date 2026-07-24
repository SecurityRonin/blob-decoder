# 5. Paranoid Gatekeeper: forbid(unsafe), panic-free lints, cargo-fuzz

Date: 2026-07-24
Status: Accepted

## Context

blob-decoder's entire job is to be pointed at bytes of *unknown, attacker-controllable*
origin — a column value, a plist `Data` field, a config string of uncertain encoding.
The single entry point `identify` must never panic, never read out of bounds, and
never trust a length or size field embedded in the input. This is the fleet's Paranoid
Gatekeeper standard for any crate parsing untrusted input.

## Decision

Adopt the fleet panic-free posture, recorded in `Cargo.toml [lints]` and enforced in
CI:

- **`unsafe_code = "forbid"`** — the crate is pure safe Rust; there is no mmap or
  FFI needing a bounded `unsafe` exception, so it takes `forbid`, not `deny`
  (`src/lib.rs` / `src/main.rs` both `#![forbid(unsafe_code)]`).
- **`unwrap_used = "deny"` + `expect_used = "deny"`**, plus `correctness`/`suspicious`
  denied and `all`/`pedantic` warned — a panicking unwrap in production code fails the
  build. Tests opt out via `#![cfg_attr(test, allow(clippy::unwrap_used, expect_used))]`.
- Every fallible step **degrades to a lower-confidence or absent reading** rather than
  panicking: detectors return `Option<Candidate>`, a failed decode becomes a `Medium`
  "magic matched but decode failed" leaf or `None`, and the engine always yields at
  least an `Unknown` reading.
- A **`cargo-fuzz` target** (`fuzz/fuzz_targets/identify.rs`) drives `identify_with_limits`
  and walks the full decoded chain of every candidate, asserting the no-panic /
  bounded-memory invariant; `fuzz.yml` builds and smoke-runs it.

## Consequences

- A malformed, truncated, or hostile blob produces a low-confidence or `Unknown`
  reading, never a crash — the tool stays usable on exactly the ragged real-world
  input it exists to triage.
- The complete `unsafe` audit surface is empty by construction (`forbid`), so the crate
  can carry the memory-safety guarantee honestly rather than as a bounded-allow caveat.
- The static posture (lints) and the empirical check (fuzzing) are complementary: the
  lints make panics unreachable by construction; the fuzzer tests that over N execs.
