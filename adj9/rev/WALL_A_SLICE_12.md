# Wall A — slice 12: candidate #1 tested in the decoder (2026-09-11)

`test_cand1.py`, `test_real_fwd.py`. Triple: `pairs_run[0]`
(ts 1789072137644, H `efa2f9b7…`, blob `251adf8d…`).

## 1. Raw search: cert-SHA1 nowhere (38/38 negative)

`SHA-1(cert)=fad0f10d…74bd`: 0 hits as byte-string, as 5 BE dwords, as 5 LE
dwords — not even 1 of its 5 dwords occurs in any of the 38 blobs. Backups
(`f9560385…`, `8691cb13…`): 0 raw hits too. Same verdict as H (slice 8):
digests are whitened through the merge, never embedded raw. A raw-match
shortcut is closed; the merge arithmetic (slice 10) is the only path.

## 2. Forward plumbing with REAL values: 11/11 sinks EXACT

Descriptors fed with real data (#4 = real H 8 dw, #9 = cert-SHA1 5 dw,
#5 = level 31, rest zeros), seed = triple second, `vm_final.py`:

```
field0  len=36 zero     sink_match=True
field4  len=8  H        sink_match=True
field5  len=1  LVL      sink_match=True
field9  len=5  CERTSHA1 sink_match=True
... ALL SINKS EXACT: True (62/62 dwords, values == rev(input BE))
```

The entire input stage (va_list → desc ptr → sink `ctx[0x20+i*8]` → `rev`
BE store) is proven with real key material, not markers. The `rev` is the
native `rev w3,w8` (field loop `0x100180`), accounted for in the assertion.

## 3. End of the line for shortcuts: 62 in, 0 recognizable out

Union of the 62 sink dwords vs the 48 real-blob dwords: **0 overlap**.
Merge output is fully decorrelated from its inputs (LENQ feedback +
ns/env entropy) — resimulation with the exact arithmetic is the only
decoder, exactly as specified in slice 10 (§4 order stands: stream-struct
model → maze exits → real bytes for the remaining 8 descriptors → 38-match
→ claim loop). Candidate #1 stays favored (only digest the lib provably
computes in-path); R2 remains the one-run disambiguator.
