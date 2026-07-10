# Security Policy

## Threat model

`blob-decoder` parses **attacker-controllable bytes** at a single entry point
(`identify`), which fans out to every decoder. The invariants are:

- `#![forbid(unsafe_code)]` — no unsafe anywhere.
- Panic-free on any input: `clippy::unwrap_used` and `expect_used` are denied in
  library code, and a `cargo-fuzz` target asserts the no-panic invariant.
- Bounded memory: every decompression (`flate2`, `snap`) is size-capped and the
  recursive unwrap is depth-capped, so a decompression bomb or an infinitely-
  nested wrapper is bounded, never fatal. The caps are configurable via `Limits`.
- Fail-graceful: a failed or coincidental decode degrades to a lower-confidence
  or absent reading; it never produces a confident-but-wrong verdict.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via a GitHub security advisory
on [github.com/SecurityRonin/blob-decoder](https://github.com/SecurityRonin/blob-decoder/security/advisories),
or by email to security@securityronin.com. We aim to acknowledge within a few
business days.
