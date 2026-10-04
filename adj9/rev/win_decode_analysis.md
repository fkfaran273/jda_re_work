# win_decode_analysis.md — the 6 genuine winning adj9 blobs, decoded and
# compared against F.py synthesis (2026-09-28)

Source: `win_capture/module_win_capture.log` (6 `authorization_header` blocks,
seconds 1790341508..1790341513, the run that booked NON-ORGANIC with no
signing-time instrumentation).  The same 6 blobs are in
`win_capture/winning_material.json`.  Analysis script: `win_decode_analysis.py`;
machine results: `win_decode_results.json`.

## 1. Decode (whiten_decoder.decode_blob)

All 6 blobs decode cleanly: `01 00 08` flags, cert SHA-1 `fad0f10d…` at
[25:45), `SHA256("")` at [79:111), all constant bytes verified (`consts_ok=True`
6/6).

| blob | second | S (record [20:24), BE) | d2 word (=bswap(S)) | head (record [3:19)) | signer path |
|---|---|---|---|---|---|
| 0 | 1790341508 | a9cf7053 | 5370cfa9 | 9e7f83cdbfbdd231ee419c5da02d8737 | Adjust-pool-27 ActivityPackageSender (fresh nSign) |
| 1 | 1790341509 | c426af1c | 1caf26c4 | 8d1a93efeff4e52b993023ff5fe4258f | Adjust-pool-25 SdkClickHandler (fresh nSign) |
| 2 | 1790341510 | a52febdb | dbeb2fa5 | c9eaebf976be1db9a3c0dedd60a45580 | adj9-chosen-sign (re-sign) |
| 3 | 1790341511 | 80dd19f6 | f619dd80 | 7c0f16bdf580fe40ffbdd814d9e91740 | adj9-chosen-sign (re-sign) |
| 4 | 1790341512 | a81eafd9 | d9af1ea8 | db59d7f63c55085aa493a55a09937b3f | adj9-chosen-sign (re-sign) |
| 5 | 1790341513 | 6e8d51e9 | e9518d6e | f3bcaef7e77772d23b52258f6c0ffbd4 | Adjust-pool-31 ActivityPackageSender (fresh nSign) |

tail2 [128:130) = `0000` on all 6 (and on all 8 corpus rows).

## 2. S values

* 6 distinct 32-bit values, deltas `+0x1a573ec9, -0x1ef6c341, -0x2452d1e5,
  +0x274195e3, -0x39915df0` — no sequence, no monotone trend, no correlation
  with the signing second.
* NOT `V ^ (pid<<16)` with the signing clock: with `V = sec ^ (usec+4000)`
  built from the capture timestamps, `low16(S) != low16(V)` for every blob
  (a constant pid could not fix the high half either).  Genuine S is a fresh
  urandom-style draw per nSign.  (The `V^(pid<<16)` seed law reproduces only
  the synthetic fill_runs emulator corpus; the poisoned win_rows S values are
  injected and also fail the clock test.)
* Byte order (IMPORTANT): the record stores the seed **big-endian** at
  [20:24).  Read little-endian those same bytes are the **d2 descriptor word**
  (`d2w`); the native seed `S = bswap(d2w)`.

## 3. F.py region comparison (S from record, pid=0)

Record head convention (corpus-validated, holds for the win blobs too): the
head is the 8 head halfword **values**, each stored **BE16**, in selector-call
order.  (Equivalent to whiten_decoder's rev16-LE-per-word `head_words`.)

Each head value is `XOR of source[7-b]` over the set bits of `(sel<<1)+3` with
`source = F._d0_source(F._d4_words(S))`.  Solving the selector per head value
gives a **single consistent selector for every one of the 8 halfwords of all
6 blobs** (each solve is unique — 2 of 65536 values hit by the 128 masks; the
joint probability of coincidence is ~1e-100).  This simultaneously proves:

* d4 materializer: `d4 = F._d4_words(S)` is byte-correct on the winning
  device (the head values are XOR-subsets of exactly those source words),
* d2: `F.region` d2 = `byteswap(seed)` = `d2w` — match 6/6,
* seed convention: S = BE32(record[20:24)) — match 6/6.

### Head selector sequences solved

```
blob 0: 2b 41 42 43 44 45 46 47     blob 3: 2b 48 42 43 44 45 46 47
blob 1: 2b 41 42 43 44 45 46 47     blob 4: 2b 48 42 43 44 45 46 47
blob 2: 2b 48 42 43 44 45 46 47     blob 5: 2b 41 42 43 44 45 46 47
```

i.e. two phases, both `prefix + stable cycle CY(i)=0x40|(i&7) from i=2`
(body then continues CY(8..71) = 0x40,0x41,…):

* `WIN_HEAD_FIRST  = (0x2B, 0x41) + CY@2`  — blobs 0, 1, 5 (fresh nSign threads)
* `WIN_HEAD_RESIGN = (0x2B, 0x48) + CY@2`  — blobs 2, 3, 4 (adj9-chosen-sign
  re-sign path) — the split correlates 6/6 with the signing thread captured in
  the log.

`F.py HEAD_FIRST (0x22,0x2E)` / `HEAD_RESIGN (0x2B,0x07,0x22,0x2E)` match
**0/6** — those are the *test device's* phases (they do reproduce the corpus
device, 6/8 full regions in all_signings).

## 4. End-to-end synthesis proof

For each blob, rebuilding the record purely from `(second, S, phase)` — head
via F.py selector law, d2 = S BE, cert SHA-1, SHA256(""), constants, tail2
`0000` — reproduces the genuine record **byte-exactly (6/6)** with only the
32-B block [46:78) borrowed, and `make_header(second)` reproduces the 16-B
header 6/6 (also 8/8 on the corpus).  `whiten_forward(record, header)` then
reproduces whitened body bytes blob[16:160) exactly for every chunk (9/9).

## 5. The 32-B block [46:78) and blob[160:192)

* The block is **not** the payload HMAC: the JCA `t1_a_out` / `nsign_in
  arg3_hex` values (key2 HmacSHA256 over the payload, e.g. `2adeb46f…`) never
  equal the block.
* No preimage found among ~40 tested SHA-256 combinations of (S, head, d2,
  d0, d4, record prefixes, blob prefixes, double hashes, +0e*14) on the 8
  corpus rows whose full region is known.
* body_decoder.py/vm_inverse.md identify it as VM-computed hash material
  "hash-like in (head, S, d4[4]…)" produced by the unresolved VM stage
  (vm_inverse §4, 3662 unresolved steps).  Only `fin_vm2.FinEx` (the
  pure-Python VM emulator) computes it, and it also reproduces the trailing
  32-B digest blob[160:192) (remint check).

## 6. Genuine-vs-synthetic difference — exact list

| item | F.py model (test device) | winning device (genuine) | status |
|---|---|---|---|
| d4 | `_d4_words(S)` | same | **match 6/6** (proven via head source words) |
| d2 | `byteswap(S)` | same | **match 6/6** |
| d0 head phase | `(0x22,0x2E)`/`(0x2B,0x07,0x22,0x2E)` + cycle | `(0x2B,0x41)`/`(0x2B,0x48)` + cycle@2 | **DIFFERENCE #1 — now enumerated** |
| S provenance | `V^(pid<<16)` (clock) | fresh urandom draw | **DIFFERENCE #2 — irrelevant for minting** |
| record layout/whitening/header | same | same | **match 6/6** |
| block [46:78) | VM-only | VM-only | **DIFFERENCE #3 — open function** |
| tail2 | `0000` | `0000` | match (constant in all 14 observations) |
| tail32 blob[160:192) | VM-only | VM-only | **DIFFERENCE #4 — open function** |

## 7. Verdict

* **The region (d0 head, d2, d4) is fully synthesizable in pure Python today**:
  take any S, `F._d4_words(S)`, the selector law with the winning device's
  phases `WIN_HEAD_FIRST=(0x2B,0x41)` / `WIN_HEAD_RESIGN=(0x2B,0x48)` (+CY@2),
  d2 = `byteswap(S)`.  The last "unknown head phase" gap for the winning
  device is CLOSED.
* **A full 192-B blob is synthesizable in pure Python only via `fin_vm2`**
  (the pure-Python VM emulator — proven to remint complete blobs); the fast
  analytic path is blocked solely by the 32-B block [46:78) and the trailing
  digest blob[160:192) functions (vm_inverse §4 blocker).  Everything else —
  header (`make_header(second)`), record constants, whitening — is already
  modeled byte-exactly.
