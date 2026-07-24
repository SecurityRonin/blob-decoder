# 6. CLI ships by default; a lean library build is the opt-out

Date: 2026-07-24
Status: Accepted

## Context

The fleet's Batteries-Included default says a tool must do the whole job from one
artifact — capability that isn't compiled in isn't there when the examiner needs it.
blob-decoder has two audiences: an analyst who runs `blob-decode` on an opaque value,
and a fleet analysis crate that links the engine to decode BLOBs inline. The analyst
must not have to know a feature flag to get the CLI; the linking library must not be
forced to pull `clap` it will never call.

## Decision

- **`default = ["cli"]`** — the CLI ships by default, because blob-decoder is an
  analyst tool (`Cargo.toml` comment: *"The CLI ships by default (blob-decoder is an
  analyst tool)."*). `cargo install blob-decoder` yields the working `blob-decode`
  binary with no flags.
- The **`cli` feature gates only the CLI-only dependency** (`clap`, `dep:clap`) and the
  `[[bin]]` target (`required-features = ["cli"]`); the library engine is fully usable
  without it.
- A library consumer wanting a lean build sets **`default-features = false`**, dropping
  `clap` while keeping the full identify/decode engine and all format decoders.

This is the narrow, sanctioned use of `default-features = false`: the slim path exists
**for outside/library consumers**, never as a way to amputate forensic capability from
the shipping tool. No decode capability is behind a feature flag — every format the
engine knows is always compiled into both the library and the binary.

## Consequences

- The zero-config path (`cargo install`) gives the analyst the complete tool; the
  zero-knowledge user cannot accidentally build a CLI-less or capability-reduced
  artifact.
- A fleet analysis crate links `blob-decoder` with `default-features = false` and gets
  the engine without a CLI-arg-parser in its dependency tree.
- There is no feature that removes a *format* from the build, so a decode never
  silently returns less than the bytes contain.
