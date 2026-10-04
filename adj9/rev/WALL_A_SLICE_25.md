# Wall A — slice 25: `0xba4a8` = Java-interop claim fetcher (2026-09-11)

Fn `0xba4a8–0xbb548` (~0xAA0 B), flattened, hub **`0xba674`**.

## Call inventory (all verified)

| site | target | role |
|---|---|---|
| ×2 | `blr [x8+0xb8]` (idx 23) | `AllocObject` (result holders, no ctor) |
| `0xbabf4` | `blr [x8+0xf8]` (idx 31) | `CallObjectMethodV` — obj=x22, methodID=`[sp+0x30]` |
| `0xbb110` | `blr [x8+0x110]` (idx 34) | `CallBooleanMethodV` (check) |
| `0xbaa80` | `blr [x8+0x538]` (idx 107) | static fetch (`CallStaticObjectMethodV`-class) |
| `0xba980` | `bl 0x1483e0` | property/getauxval env check |
| ×3 | `bl 0x9afa4` | internal helper |
| + | `strb/ldrb` webs, `eor` | byte/string handling |

## Key evidence

- `Map.get`-shaped JNI signature `(Ljava/lang/Object;)Ljava/lang/Object;`
  decrypted INLINE (XOR `0xbe` NEON loop) at `0xbb044` + `0xbb250`
  (`adr x28,#0x153910` + decrypt-and-write-back). In-use, twice.
- **No `GetMethodID` (`0x2f0`) anywhere in the fn** ⇒ methodIDs (incl. the
  get-method + the boolean check) arrive from OUTSIDE (caller args / cached
  struct). The *name* `get` has no in-range xref either (computed or
  external) — so the call could be `Map.get` OR another `(Object)Object`
  method; the sig alone doesn't close it.
- Nearby xrefs: `'size'` (`0xb59b8/0xb5ddc`), `'31 T'` (`0xb638c/0xb66e4`
  + the two decrypt sites) — consistent with map-size checks + time-ish
  strings, not yet tied to call sites.

## What this means for the 7 unknowns

`0xba4a8` is the bridge that pulls Java-map claims into native buffers —
i.e. plausibly where #0's 144 B (and #3's string) get built. Its two call
sites: stamp `0x12c3b4` (`x0=x20, x2=[sp+0x40], x3=[x29−0x48],
x4=x29−0x30`) and `0xbb548+0xbba34`. Full claim list (WHICH keys → #0
composition) needs the hub-`0xba674` unflatten run (same tooling as
`0x24a40`/`0x10594`) or methodID provenance from the callers' frames
(`[sp+0x30]`-class slots). Next: unflatten `0xba674`.
