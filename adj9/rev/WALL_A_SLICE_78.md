# Wall A — slice 78: BODY DECODED — the envelope, end to end, live-proven (2026-09-13)

This slice closes Wall A. Every claim below is verified against a live signing
captured in the same run (`device/whcap_hits7.json` — 39,673 EMIT events with
(sink, position, value), paired with `device/adj9_wh4.log` nsign blobs).

---

## 1. THE ENVELOPE, COMPLETE

The signing VM writes ONE output stream. The 192-byte blob is its **first 48
dwords**, big-endian:

```
OUTPUT[0..4)   = 16-B header  = Random3(time) draws 1–8, pairwise XOR   (PROVEN 44/44)
OUTPUT[4..48)  = 176-B body   = the whitened record                    (PROVEN 44/44 this slice)
OUTPUT[48..52) = repeat of body[36..40)  (4-word tail artifact)
OUTPUT[52...]  = plaintext claims (adjacent in the same stream, NOT in the blob)
```

Live proof (signing ts 1789240514239, sink `…f52fd970`):
- header == OUTPUT[0..4) → **True**
- body == OUTPUT[4..48) → **True** (44/44 dwords)

## 2. THE WORKHORSE IS A COPIER (`0x12a860` loop, fully read)

```
out[w21 + i] = workspace_stream[TOP + i]   for i in 0..OUTLEN−1
```
LENQ reads a workspace window, EMIT writes it verbatim. No value transform.
All whitening happens earlier, in the value-routed merge passes, which place
claim-derived values at positions `idx = TOP + n` (position arithmetic). This
explains: total diffusion, zero raw containment, no per-word transform fit.

## 3. THE BODY'S CONTENT (what the server "decrypts")

The body = the whitened record built from 147 input dwords (Agent B, from live
fieldloop captures — **supersedes slice 7's "62 dwords"**):

| descriptor | len (dw) | content |
|---|---|---|
| #0 | 36 | core record (env verdicts/telemetry) |
| #9 | 5 | cert-SHA1 `fad0f10d…74bd` (verified live: tail `ae7d74bd`) |
| #8 | 4 | runtime buffer (NOT the SHA-1 prefix — slice 26 corrected) |
| #4 | 8 | H = TEE-HMAC (opaque per-device tag) |
| #2 | 1 | master struct u32 |
| #7 | 1 | word of #10 (`0x168`/`0x183` observed live) |
| #10 | RT | claims blob (the ASCII seen at OUTPUT[52..113) = its source) |
| #5/#6 | 1+1 | zero (proven constants) |
| #1/#3 | 0 | empty |

va_list pass order (live): `#0,#9,#8,#4,#2,#7,#10,#5,#6,#1,#3` — NOT the
mkdesc build order.

## 4. CAP DECODED (the in-band feedback op)

`CAP(queue, k)`: if `count ≤ k` → writer error 4 (VM exits); else walk k
`next` links from head and **PUSH a copy of that node's value** — 542 call
sites, all on ctx[0]. (Corrects slice 45's "pad" reading: the pushed value is
the walked node's value, and the trigger is the queue count.)

## 5. THE SERVER MODEL — FINAL (unchanged, now fully evidenced)

1. Regenerate `Random3(second)` from the wall clock; match OUTPUT[0..4).
2. Re-run the same VM program over the claims **taken from the visible request
   fields** (created_at, app_version, gps_adid, store, installed_at, … — every
   claim in the plaintext region comes from the request or the device's public
   state) plus the device-bound H tag.
3. Compare/parse the regenerated body. **No key. No cipher. The TEE key never
   participates** — H rides as an opaque consistency tag.

A body can only be *decoded* with its request's claims (the whitening input);
given the request, verification is a deterministic re-simulation — exactly
"decrypt for data and data formats".

## 6. Tooling state

- `rev/vm_final.py` — executor (field loop 62/62+ validated; struct semantics
  per slice-73 fixes; 48-bit tagged-pointer masking; read-only hydration).
- `rev/hydrate.py` / `rev/recompute8.py` — full stream hydration + 90/90
  claims-copy replay (Agent A).
- `rev/extract_desc.py` + `rev/descriptors_aligned.json` — descriptor
  extraction + live cross-check 24/24 (Agent B).
- `rev/OPS_LIFT.md` — CAP contract + queue/node layout.
- `device/whcap5.js|6.js` + `device/whcap_hits*.json` — the live EMIT/LENQ
  trace harness (spawn-mode Frida, fs17root, per-signing segmentation by sink).
- `rev/WORKHORSE_DECODE.md` — the copier proof.

## 7. What "decode a pasted signature" now means

Given ONLY a signature (this session's original question):
- header → signing second (instant, offline).
- body → the whitened record; its plaintext claims are NOT recoverable without
  the request that accompanied it (the whitening input). With the request
  (as the server has), the body is fully verifiable/decodable by re-simulation.
- The envelope contains NO secrets: everything in it is derived from
  public/request data + the opaque H tag.
