# 7. MSRV floor 1.88.0, raised deliberately by the `plist` dependency

Date: 2026-07-24
Status: Accepted

## Context

Published fleet libraries keep a low, CI-verified MSRV as a compatibility feature.
blob-decoder would prefer the same low floor, but its MSRV is not a free choice — it
is the maximum required by its dependency graph, and capability wins over a low floor
when the two conflict (the fleet "MSRV yields to capability" rule).

## Decision

Declare **`rust-version = "1.88.0"`** (`Cargo.toml`) and verify it in a dedicated CI
`msrv` job (mirrored in `clippy.toml`'s `msrv = "1.88.0"`). The floor is set by the
dependency chain, not chosen for its own sake: commit `4bc15a9`
(*"set honest MSRV floor 1.88.0 (raised by plist 1.10 -> time 0.3.53)"*) records that
`plist 1.10 → time 0.3.53` pulls edition-2024 `time-core`, which requires rustc
1.88.0. The `clippy.toml` comment states it verbatim: *"This is as low as the
dependency graph allows … so 1.88.0 is the floor."*

The dev toolchain is pinned separately to the current fleet stable
(`rust-toolchain.toml` → `1.96.0`); the declared MSRV is the downstream-facing promise
and is CI-verified independently of the dev pin.

## Consequences

- The floor is *honest and measured*: it is the graph's true minimum, not a round
  number, and a CI job proves the crate builds on 1.88.0.
- Taking the `plist` bump (and its MSRV) rather than dropping or re-implementing plist
  keeps full property-list capability — the capability-over-MSRV trade the fleet
  standard prescribes for an analysis-layer crate.
- If a future dependency raises the floor again, it is recorded the same way (a commit
  naming the crate and version that forced it), so the MSRV always traces to a cause.
