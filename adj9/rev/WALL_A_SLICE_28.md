# Wall A — slice 28: smali route — pipeline confirmed, fetcher = iterator (2026-09-11)

Tooling: baksmali jar path dead (no manifest main class; jcommander/guava
missing; JBR runs it but deps absent) — used `androguard` (pip) low-level
`DEX` parsing instead (`smali3.py`, kept). No smali tree written.

## 1. Pipeline independently confirmed in Dalvik bytecode (`classes3.dex`)

- `NativeLibHelper.<clinit>`: `System.loadLibrary("signer")`; `nSign
  (Context, Object, byte[], int)→byte[]` native; `a(...)` = direct
  passthrough (matches the Xposed hook + JNI observations).
- `Signer.sign(Context, Map, Map, Map)` → `new u2(ctx, t1,
  NativeLibHelper, m1, m2, m3)` + `u2.a()`; v4-overload throws
  ("...not compatible with Adjust SDK v4..."); lockdown/exception paths
  with the exact log strings from the live logs.
- `u2.a()`: `LinkedHashMap` copy + `activity_kind`/`client_sdk` puts from
  map-e + `adj_verification` gate (`o3.a(new a0())` when flag `b`) +
  `t1.b(ctx)` → `d3.a(string)` → `t1.a(ctx, bytes)` = H (with
  Unrecoverable/InvalidKey retry paths) → `NativeLibHelper.a` → header.
- `u2.a(map, blob)`: Base64 + six `map.get(...)` in order
  `adj_signing_id, headers_id, algorithm, native_version, adj_verification`
  → `Signature %s,%s,%s,%s,%s,%s` (matches the dex `filled-new-array`
  order finding).

## 2. `0xba4a8` = map ITERATOR, not name lookup

String-table xrefs into `0xba4a8–0xbb548`: exactly 4 — the two inline
decrypt sites × (`(Object)Object` sig + `31 T`). NO claim-name strings, NO
`get`/`size`/`keySet` names. Combined with its JNI set (AllocObject ×2,
`CallObjectMethodV`, `CallBooleanMethodV`, static fetch) the consistent
reading is `hasNext/next` iteration (boolean + object calls) with allocated
holders — i.e. #0's 144 B is built by ITERATING entries (order = the
`LinkedHashMap` insertion order we hold exactly from captures), not by
looking up names. `31 T` stays unidentified (minor).

## 3. Smali verdict on the 7 unknowns

Java side ends at `(ctx, LinkedHashMap, H, level) → nSign` — everything
downstream is native-only, confirmed a second way. Smali cannot supply
#0/#2/#7/#8/#10/ns directly. What it supplies: exact Java-side assembly
(above), the iteration (not lookup) nature of #0's construction, and the
full `sign()` call graph for any future Java-hook placement. Net: #0
composition = f(iterated map entries in captured insertion order) —
testable against the golden 50-map once the iteration body (hub `0xba674`
walks) is lifted.
