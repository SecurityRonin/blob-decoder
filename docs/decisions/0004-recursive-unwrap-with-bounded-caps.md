# 4. Recursively unwrap nested wrappers, bounded by depth, output-size, and input caps

Date: 2026-07-24
Status: Accepted

## Context

The differentiating case is a blob wrapped several layers deep — a base64'd, gzip'd
binary-plist, or a hex-encoded Snappy stream. A tool that identifies only the
outermost layer ("this is base64") hands the analyst back another opaque blob and
makes them run the tool again by hand. The value is in reporting the *whole chain*,
each link scored and cited.

But recursion over attacker-controllable bytes is a denial-of-service surface: a
decompression bomb (kilobytes inflating to gigabytes) and an infinitely-nested
wrapper (base64 of base64 of base64 …) must both be bounded, or the tool becomes the
attack.

## Decision

A *wrapper* kind (`BlobKind::is_wrapper` — gzip, zlib, Snappy, base64, hex) nests the
identification of its **decoded payload** in `Candidate::inner` as a `DecodedChain`,
built by `build_chain` re-entering `identify_with_limits` on the decoded bytes. So a
`base64 → gzip → binary-plist` blob reports the full chain, best reading at each
link.

Three caps in `Limits` bound the recursion on untrusted input:

- **`max_depth`** (default 8) — `build_chain` stops recursing at the cap and emits a
  `depth_capped` `Unknown` reading naming the undecoded head bytes; the infinite-nest
  backstop.
- **`max_output`** (default 64 MiB) — every decompression goes through `bounded_read`,
  which reads at most `cap + 1` bytes (`take(cap as u64 + 1)`) and truncates, flagging
  `capped` when the stream had more. A decompression bomb is bounded to `cap`, never
  allocated in full.
- **`max_input`** (default 128 MiB) — inputs larger than this skip the *heuristic*
  scanners (base64/hex/text/protobuf, which scan the whole blob); magic-signature
  detection still runs, so huge inputs get magic-only identification cheaply.

`identify_with_limits(bytes, limits, depth)` is public so callers can tighten the
caps (the fuzz target runs with `max_depth: 6`, `max_output`/`max_input` of 1 MiB).

## Consequences

- The headline capability — full-chain decode of nested wrappers — is delivered by
  the same recursive entry point that enforces the caps; there is no unbounded path.
- A `capped` flag on `DecodedChain` tells the analyst the payload reading is of a
  truncated prefix (a possible bomb), rather than silently presenting a partial decode
  as complete (fail-loud).
- The `depth_capped` and `Unknown` fallbacks surface the raw head bytes, so a bounded
  stop is diagnosable, not a dead end.
