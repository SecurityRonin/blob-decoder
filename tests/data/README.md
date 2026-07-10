# Test data provenance

Small, self-produced fixtures committed so the plist decode paths run everywhere
(not only where `python3` is installed). Larger, tool-produced inputs are
generated at test time by `tests/common/mod.rs` and are not committed.

| File | Source | Contents | MD5 | License | Used by |
|---|---|---|---|---|---|
| `sample.bplist` | Generated with CPython `plistlib.dumps(..., fmt=FMT_BINARY)` (Python 3.11) | Apple binary plist of `{"name":"blob","ints":[1,2,3],"ok":true}` | `d9b5d192fc830e705aecc6586571d2fa` | CC0-1.0 (self-authored, no third-party content) | `tests/fixtures.rs` |
| `sample.plist` | Generated with CPython `plistlib.dumps(..., fmt=FMT_XML)` (Python 3.11) | Apple XML plist of the same dict | `65852730501a0fd8f0dc0a0079b5d197` | CC0-1.0 (self-authored) | `tests/fixtures.rs` |

Regenerate with:

```bash
python3 -c "import plistlib; open('tests/data/sample.bplist','wb').write(plistlib.dumps({'name':'blob','ints':[1,2,3],'ok':True}, fmt=plistlib.FMT_BINARY))"
python3 -c "import plistlib; open('tests/data/sample.plist','wb').write(plistlib.dumps({'name':'blob','ints':[1,2,3],'ok':True}, fmt=plistlib.FMT_XML))"
```

These are structural fixtures for identification tests, not a ground-truth
correctness oracle for the `plist` crate itself (the `plist` crate is the
established reference for the format; `blob-decoder` only dispatches to it). The
tier-2 validation — real inputs produced by independent tools (system `gzip` /
`base64`, python3 `zlib`) and decoded back — lives in `tests/magic.rs`,
`tests/nested.rs`, and `docs/validation.md`.
