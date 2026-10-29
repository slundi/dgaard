# dgaard-ffi

C ABI for the [`dgaard-engine`](../dgaard-engine) domain filtering engine. Lets
C, C++, Go (cgo), Python (ctypes), Zig, Nim — anything that speaks the C ABI —
run the same classification pipeline the `dgaard` daemon uses.

Licensed Apache-2.0, like the engine, so linking it into a proprietary binary
is fine.

## Building

```bash
cargo build -p dgaard-ffi --release
```

Produces `libdgaard.so` (shared) and `libdgaard.a` (static) in `target/release`.
Fully static targets such as `aarch64-unknown-linux-musl` — the OpenWrt build —
produce `libdgaard.a` only; cargo warns that it is skipping the `cdylib`, which
is expected.
The header is committed at [`include/dgaard.h`](include/dgaard.h); regenerate it
with `just ffi-header` after changing anything under `src/`.

```bash
cc -I dgaard-ffi/include my_app.c -L target/release -ldgaard -o my_app
```

`just ffi-demo` compiles and runs [`examples/demo.c`](examples/demo.c) against a
fresh build — the quickest way to check your toolchain.

## Shape of the API

Two opaque handles:

| Handle           | Lifetime                                                  | Thread safety                                                |
| ---------------- | --------------------------------------------------------- | ------------------------------------------------------------ |
| `dgaard_engine`  | built once from a config, freed with `dgaard_engine_free` | immutable and `Sync` — share one pointer across every worker |
| `dgaard_verdict` | one classification, freed with `dgaard_verdict_free`      | owned by the thread that created it                          |

A verdict owns its payloads, so the engine and the verdicts it produced can be
freed in either order.

```c
dgaard_engine *engine = dgaard_engine_new_from_file("/etc/dgaard/config.toml");
if (engine == NULL) {
    char message[256];
    dgaard_last_error(message, sizeof message);
    fprintf(stderr, "dgaard: %s\n", message);
    return 1;
}

dgaard_verdict *verdict = dgaard_classify(engine, "kq3v9z7x1j4m2p8w.biz");
if (verdict && dgaard_verdict_action(verdict) == DGAARD_ACTION_BLOCK) {
    printf("blocked: reason=%d score=%u\n",
           dgaard_verdict_block_reason(verdict),
           dgaard_verdict_score(verdict));
}

dgaard_verdict_free(verdict);
dgaard_engine_free(engine);
```

Three constructors:

- `dgaard_engine_new_heuristics()` — default config, **no lists, no filesystem
  access**. DGA, structure, IDN and query-type checks only. The right choice
  for embedding detection without deploying list files.
- `dgaard_engine_new_from_file(path)` — full pipeline, lists read from disk.
- `dgaard_engine_new_from_toml(text)` — same, with the config supplied inline.

## Strings

Every string accessor writes into a buffer you own, under the `snprintf`
convention: the return value is the length the text **needs**, excluding the
terminator.

```c
size_t needed = dgaard_verdict_block_text(verdict, NULL, 0);  /* ask the size */
char *text = malloc(needed + 1);
dgaard_verdict_block_text(verdict, text, needed + 1);         /* fill it      */
```

A return value `>= capacity` means the text was truncated — always on a UTF-8
character boundary, never mid-character. Nothing this library returns needs to
be `free()`d except the two handles.

## Failure is never a verdict

| Call shape                                   | Failure value             |
| -------------------------------------------- | ------------------------- |
| constructors, `dgaard_classify`              | `NULL`                    |
| `dgaard_is_*`, `dgaard_score`                | `-1`                      |
| `dgaard_verdict_action`                      | `DGAARD_ACTION_ERROR`     |
| `dgaard_check_q*`, `dgaard_verdict_*_reason` | `DGAARD_REASON_ERROR`     |
| numeric payloads                             | `NaN` (test with `isnan`) |

None of those values can come out of a successful call, so a NULL pointer, a
non-UTF-8 domain or a config that failed to parse can never be mistaken for
"this domain is fine". `dgaard_last_error(buf, cap)` explains the most recent
failure **on the calling thread**; a successful call clears it.

## Reason payloads

`dgaard_reason` tags are stable and append-only. Each carries at most one
payload, reachable through the `_number` and `_text` accessors:

| Tag                                                        | Payload                                                                 |
| ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| `DGAARD_REASON_HIGH_ENTROPY`                               | number — entropy in bits per character                                  |
| `DGAARD_REASON_LOW_ENTROPY`                                | number — length of the repetitive label                                 |
| `DGAARD_REASON_FORBIDDEN_QTYPE`                            | number — RFC 1035 type code                                             |
| `DGAARD_REASON_LOW_TTL`                                    | number — TTL in seconds                                                 |
| `DGAARD_REASON_CUSTOM_FLAG`                                | number — custom-flag bit index (16–31)                                  |
| `DGAARD_REASON_BANNED_KEYWORD`                             | text — the matched keyword                                              |
| `DGAARD_REASON_GEOIP_SUSPICIOUS`                           | text — ISO 3166-1 alpha-2 country code                                  |
| `DGAARD_REASON_STATIC_BLACKLIST`, `DGAARD_REASON_ABP_RULE` | text — a coarse stage label, _not_ the source filename (see the header) |

`dgaard_verdict_reason_count` is exact. Indices `0 .. count` are always
populated — the list is the full set of contributing heuristics, never a
truncated window into a fixed-size array.

## Versioning

`dgaard_abi_version()` returns the ABI revision the library was built with;
`DGAARD_ABI_VERSION` is what your header declares. Compare them at startup to
catch a header/library mismatch. The revision is bumped whenever an enum
variant is appended or a signature changes; existing tag values are never
renumbered.

## Not covered

Response-side inspection — DNS rebinding, low TTL, CNAME cloaking, GeoIP and
ASN checks on upstream answers — needs the answer records, which this ABI does
not yet accept. Those reason tags are defined so they do not have to be
renumbered later, but only the query-side pipeline can produce them today.

Android consumers should use the UniFFI binding described in
[`docs/Roadmap-Android.md`](../docs/Roadmap-Android.md) rather than this C ABI;
it generates idiomatic Kotlin instead of requiring hand-written JNI glue.
