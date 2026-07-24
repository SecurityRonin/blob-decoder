# 3. Return non-exclusive, scored, cited candidate readings — never one verdict

Date: 2026-07-24
Status: Accepted

## Context

An opaque blob is frequently underdetermined. Bytes that are valid hex are usually
also valid base64; a run of printable ASCII is *technically* decodable as base64 to
gibberish; 16 arbitrary bytes form a syntactically valid UUID; a large fraction of
random byte strings parse cleanly as "valid protobuf." A tool that picks a single
answer for an ambiguous blob is guessing, and a confident wrong guess in a forensic
context is worse than an honest ranked set. This is the fleet epistemology rule —
observe and rank, do not assert a conclusion the evidence does not carry.

## Decision

`identify` returns a **`Vec<Candidate>`** — every plausible reading, sorted best
first — not a single result. Each `Candidate` carries:

- a `BlobKind`,
- a **`Confidence`** score (`Low < Medium < High`) reflecting the *strength of the
  check*, not a wish (`src/lib.rs`, `Confidence` docs):
  - **High** — a strong near-unique magic signature or a full successful parse
    (`bplist00`, `1f 8b`, a valid RFC 1950 header, a parseable JSON object, a
    canonical hyphenated UUID string);
  - **Medium** — a magic matched but the payload failed to fully decode, or a
    heuristic wrapper whose decoded payload was itself recognised;
  - **Low** — a coincidence-prone structural heuristic (16 bytes as a UUID,
    base64/hex decoding only to opaque bytes, bare printable text);
- a `citation` naming the authoritative spec the kind was matched against
  (`BlobKind::citation` — RFC 4648, RFC 1952, RFC 9562, etc.), so a reading is
  traceable to a format definition, not an assertion;
- a `summary` of *what was found* (and, for `Unknown`, the raw head bytes via
  `head_hex` — surfacing the offending value, never a bare "unrecognized").

A low-confidence reading **lowers the rank, never hides the finding**: sorting is by
descending `Confidence`, then a specificity tiebreak (`kind_rank`), then label. The
engine always returns at least one candidate — an `Unknown` reading that reports the
head bytes when nothing else matched.

## Consequences

- The output is honest about ambiguity: the base64/UTF-8 double-reading of the same
  bytes both appear, ranked, rather than one being silently chosen (README example).
- Confidence is a published contract callers can filter on; the CLI maps it to
  `HIGH`/`MED`/`LOW` and to a pipeline exit code (`2` when the best reading is
  `Unknown`).
- Downstream fleet analysis layers can take `candidates[0]` for a best-guess or walk
  the whole set for a review UI — the ranking is advisory, the set is complete.
