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

## V8 serialized-value fixtures (`data/v8/*.v8`)

Real output of V8's `ValueSerializer`, minted on this host by node's
`v8.serialize(value)` — the exact serializer Chromium/V8 use. The **known JS
input value is the oracle** (tier-2): the deserializer must reproduce it. One
`<name>.v8` per case; the case → input-value map lives in
`scripts/mint_v8_fixtures.mjs` (the verbatim generator) and each is asserted in
`tests/v8_deserialize.rs`.

Notable: `uint8array.v8` / `int32array.v8` are **not** standard V8/Blink — node
serializes typed arrays through its own `kHostObject` (`0x5C`) delegate, so those
two are used as *host-object → fail-loud* cases, never as typed-array oracles.
`arraybuffer.v8` (tag `B`) is the standard, decodable form.

Regenerate:

```bash
node scripts/mint_v8_fixtures.mjs      # requires node with a V8 engine
```

License: CC0-1.0 (self-authored input values; bytes are V8 engine output).

## Blink serialized-script-value fixtures (`data/blink/*.blinkssv`)

**Real** Chromium IndexedDB values, captured verbatim from a live
`file__0.indexeddb.leveldb` written by headless Google Chrome on this host, then
sliced to the exact SerializedScriptValue a IndexedDB extractor yields (starting
at the Blink version tag `FF 15`). Each begins with the Blink envelope
`FF 15` (wire version 21) + `FE` trailer (8-byte BE offset + 4-byte BE size) +
`FF 10` (V8 version 16) + the V8 payload. The **stored JS value is the oracle**
(tier-2).

| File | Stored JS value | MD5 |
|---|---|---|
| `idb_string.blinkssv` | `'hello'` | `ace4c6298739bc2090f36424c2d24b10` |
| `idb_array.blinkssv` | `[1, 2, 3]` | `c281f818a531f5ca2d777d7436ce5d32` |
| `idb_object.blinkssv` | `{name:'x', list:[1,2,{deep:'y'}], when:new Date(1600000000000), flag:true, count:42}` | `02a8f526f4c9bc6084b09c9e52a03d49` |

Recapture: drive headless Chrome to `indexedDB.put(value, key)` (see
`docs/validation.md` for the exact page + extraction), then slice each stored
value from the leveldb log at its `FF 15 FE … FF 10` envelope. Asserted in
`tests/blink_deserialize.rs`.

License: CC0-1.0 (self-authored input values; bytes are Chromium engine output).
