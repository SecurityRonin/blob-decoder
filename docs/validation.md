# Validation

`blob-decoder` decodes nothing itself — it dispatches to established crates
(`plist`, `flate2`, `snap`, `base64`, `hex`, `uuid`, `serde_json`), each already
the reference implementation for its format. What this crate adds, and therefore
what is validated here, is the **identification, scoring, and recursive unwrap**.

## Evidence tiers

Following the Evidence-Based Rigor tiering (who confirms the result):

- **Tier 2 — real inputs, independent producer.** The identification and decode
  tests feed inputs produced by tools *other than* the decoder crate under test,
  then assert the reading and the recovered payload. Because an independent tool
  authored the artifact, a wrong decode cannot pass by agreeing with a fixture we
  hand-encoded.
- **Tier 3 — committed structural fixtures and adversarial cases.** Small
  self-produced plist fixtures (documented in `tests/data/README.md`) keep the
  plist paths exercised everywhere, and hand-built malformed inputs assert
  graceful degradation. These specify behaviour of *our own detection rules*; they
  are not the sole oracle for any value-producing decode.

## Tier-2 checks (independent producers)

| What | Producer (independent of the decoder) | Decoder | Assertion |
|---|---|---|---|
| Binary plist | CPython `plistlib` (`FMT_BINARY`) | `plist` crate | identified `BinaryPlist`, root dict described |
| XML plist | CPython `plistlib` (`FMT_XML`) | `plist` crate | identified `XmlPlist` |
| gzip → JSON | system `gzip` | `flate2` + `serde_json` | identified `Gzip`, payload recovered as `Json` |
| zlib → JSON | CPython `zlib.compress` | `flate2` | identified `Zlib`, payload recovered as `Json` |
| base64 → gzip → JSON | system `base64` + `gzip` | full chain | whole `Base64 → Gzip → Json` chain reported |
| UUID string | system `uuidgen` | `uuid` crate | identified `Uuid`, High confidence |

These live in `tests/magic.rs`, `tests/nested.rs`, and `tests/identifiers.rs`, and
skip cleanly when a producer tool is absent.

## Robustness (adversarial)

`tests/robustness.rs` and the `cargo-fuzz` `identify` target assert the untrusted-
input invariants: no panic and bounded memory on truncated streams, a 64 MiB-of-
zeros zlib bomb (capped at the configured output limit, never allocated in full),
invalid base64, deeply-nested wrappers (stopped at the depth cap), and random
bytes (which degrade to a Low/Unknown reading, never a confident verdict).

## Honest scoring

Confidence reflects the *strength of the check*, not a wish:

- **High** — a strong, near-unique magic signature or a full successful parse.
- **Medium** — a magic matched but the payload failed to decode, or a heuristic
  wrapper (base64/hex) whose decoded payload was itself recognised.
- **Low** — a coincidence-prone heuristic: 16 arbitrary bytes read as a UUID,
  base64/hex text decoding only to opaque bytes, or plain printable text.

A blob that is genuinely underdetermined returns several readings; a low-
confidence reading lowers the rank, never hides the finding.
