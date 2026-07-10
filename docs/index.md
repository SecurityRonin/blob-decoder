# blob-decoder

Hand it opaque bytes of unknown type. `blob-decoder` identifies what they are,
decodes them, and reports **scored, cited candidates** — recursively unwrapping
nested wrappers (a base64'd, gzip'd binary-plist is reported as the full
`Base64 → Gzip → BinaryPlist` chain).

The decoding is delegated to mature crates (`plist`, `base64`, `hex`, `uuid`,
`flate2`, `snap`, `serde_json`). The value this crate adds is the orchestration
layer: identify → dispatch → score → recursively unwrap, plus a clean forensic
result type that is honest about ambiguity.

```console
$ B64=$(printf '{"user":"alice"}' | gzip | base64 | tr -d '\n')
$ blob-decode --string "$B64"
blob-decode: 48 bytes; 2 candidate reading(s), best first:
  [MED ] base64 text — base64 text; decodes to 36 bytes
       cite: RFC 4648 §4-5 (Base 64 / Base64url)
       decodes to 36 bytes:
    [HIGH] gzip stream — gzip stream; 16 bytes decompressed
         cite: RFC 1952 (GZIP file format)
         decodes to 16 bytes:
      [HIGH] JSON — JSON object with 1 keys
           cite: RFC 8259 (JSON)
  [LOW ] UTF-8 text — UTF-8 text preview: "H4sIAD4mUWoAA6tWKi1OLVKyUkrMyUxOVaoFAPcasFUQAAAA"
       cite: RFC 3629 (UTF-8)
```

The base64 text is also *technically* UTF-8, so that reading is offered too — at
Low confidence, ranked last. `blob-decoder` never hides an interpretation; it
scores it.

See [Validation](validation.md) for how identification and decode are checked
against independent tools and real inputs.

---

[Privacy Policy](https://securityronin.github.io/blob-decoder/privacy/) · [Terms of Service](https://securityronin.github.io/blob-decoder/terms/) · © 2026 Security Ronin Ltd
