# whiten_decoder — the INVERSE of the adj9 whitening cipher, validated

Date: 2026-09-28. Files: `rev/whiten_decoder.py` (the inverse + embedded
constants), `rev/_wdec_explore.py` (trace extraction/derivation used to obtain
and verify them). Nothing existing was modified.

---

## 1. Headline

**The adj9 whitening cipher is now fully invertible in pure Python.** Every
constant was extracted once from the VM wire trace, every step was verified
individually against the trace, and the end-to-end round trip is byte-exact on
two independent traces and on all real captured blobs. Decode cost: ~20 ms per
192-B blob, no VM, no probing (the previous route, `body_decoder.py`, needed
10–12 FinEx VM runs of ~30 s each at every target).

## 2. The forward model — verified, with one scope correction

Per 16-B chunk of the 144-B record (9 chunks), exactly as postulated:

```
WA0 = blob[0:16)                 the header itself travels in the blob (the IV)
WA_k = output of chunk k-1       CBC-style chain
chunk = plaintext[16k:16k+16) ^ WA_k
14 rounds r = 0..13:
    chunk[i] ^= 0x55 ^ KB[16r+i]        (pc 0x111c68)
    chunk[i]  = T[chunk[i]] ^ 0x55      (pc 0x111f70)
    chunk     = pi1(chunk)              out[PI[i]] = in[i]
    if r < 13: chunk = F(chunk)         32-B GF(2) linear map, 4-B blocks
chunk[i] ^= 0x55 ^ KB[224+i]            final sweep
body[16k:16k+16) = chunk                == blob[16+16k : 32+16k)
```

**Scope correction (the "digest" is not whitened).** The trace contains
exactly 2016 = 9×14×16 S-box events, 144 = 9×16 header-XOR events and 135
key-sweep phases — all confined to MAIN [1134..1278). There are **zero**
whitening events on MAIN addresses ≥ 1278 and zero whitening pcs on any other
stream. blob[160:192) (words 40..47) is a separate 32-B digest built by other
machinery after the record is whitened (a copy loop feeds every 4th byte of
the whitened body into a hash at MAIN [620..655)); it never passes through
this cipher. `_inv2_chunks.py`'s digest-window assumption was wrong;
`vm_inverse.md` already said the same.

## 3. The constants (all extracted from `_inv2_row7_real.json.gz`,
cross-checked against `_inv2_row7_rand.json.gz`)

| constant | value / check |
|---|---|
| T | 256-B S-box, a true permutation (256/256 distinct, 2016 events, 0 conflicts) |
| KB | 240 B; `KB[0:16] = 43fc368804c8ed1b17e5c8f603002f46`, `KB[224:240] = 208b07e8e2c7c9f30d01aa5ca3cc74cc`; all 240 positions observed, constant across all chunks, 0 conflicts — identical in both traces |
| pi1 | `out[PI[i]] = in[i]`, `PI = [0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3]` (matches the `SITES_DIAG1_ORDER` PI in `_inv2_model.py`); identical in both traces |
| F | diag-2 block map: **linear** (constant = 0), circulant 32×32 GF(2) matrix; 936/936 block samples (468 real + 468 rand) with 0 mismatches; `F_MINV` exact inverse (M·M⁻¹ = I checked, 2000 random round-trips) |
| WA law | WA(chunk k) = blob[16k:16k+16) — 9/9 chunks in both traces (chunk 0 uses the header, which the blob carries) |

## 4. Validation

### 4a. Row 7 traces — forward AND inverse byte-exact

| test | result |
|---|---|
| `whiten_forward(record, blob[0:16)) == blob[16:160)` — real trace | **True (144/144 B)** |
| same — rand trace (completely different region) | **True (144/144 B)** |
| `whiten_body_inverse(blob[16:160)) == record` — real trace | **True (144/144 B)** |
| same — rand trace | **True (144/144 B)** |

### 4b. Corpus (pair_h3 blobs vs all_signings regions)

All 8 captured blobs decode with **consts_ok = True** (flags `01 00 08`, `02`,
`03`, `04`, `05`, SHA256(""), `06 01 07`, `00*14`, `0e*14`, and cert SHA-1
`fad0f10d…` at [25:45) — 76 bytes pinned).

| row | consts | region match | phase | seed | d2 |
|---|---|---|---|---|---|
| 0 | True | **True** | HEAD_FIRST | f516aa41 | 41aa16f5 |
| 1 | True | **True** | HEAD_FIRST | 12b21e6b | 6b1eb212 |
| 2 | True | False (pairing artifact, see below) | HEAD_FIRST | afcaca2e | 2ecacaaf |
| 3 | True | None (pairing artifact) | — | 9b7d7469 | 69747d9b |
| 4 | True | **True** | HEAD_FIRST | afcaca2e | 2ecacaaf |
| 5 | True | **True** | HEAD_FIRST | 985f5c11 | 115c5f98 |
| 6 | True | **True** | HEAD_FIRST | 6a896959 | 5969896a |
| 7 | True | **True** | HEAD_FIRST | 96821afb | fb1a8296 |

**6/6 for the task's rows (0,1,4,5,6,7)** — decoded (d0 144 B, d2 4 B, d4
32 B) match `all_signings.json` byte-exact, via the region laws
`d4w = F._d4_words(BE32(rec[20:24)))`, `d0w = F._d0_words(d4w, head)`,
`d2 = LE32(rec[20:24))`.

Rows 2/3 are **not decoder failures** — they are `pair_h3.py` capture-pairing
artifacts, proven by cross-pairing on the decoded d2 word:
* pair_h3 rows 2 and 4 carry the **same captured blob** (its decoded d2
  `2ecacaaf` equals all_signings[4].d2 — the sample-2 capture was duplicated
  onto sample 4);
* blob 3 decodes cleanly (d2 `69747d9b`) but matches **no** all_signings
  sample — that capture's descriptor set was never captured.
Every all_signings row that has a captured blob (0,1,4,5,6,7) matches
full-region byte-exact: **there are zero decode misses.**

### 4c. Genuine winning blobs (`win_capture/winning_material.json`, from
`module_win_capture.log`)

All 6 genuine winning blobs **decode cleanly**: consts_ok = True on every one
(same 76 pinned constant bytes incl. the app cert SHA-1), tail2 = `0000` on
all. Header law identifies them as six consecutive signings at seconds
**1790341508…1790341513**:

| blob | second | d2w | F_seed | head (record[3:19)) |
|---|---|---|---|---|
| 0 | 1790341508 | 5370cfa9 | a9cf7053 | 9e7f83cdbfbdd231ee419c5da02d8737 |
| 1 | 1790341509 | 1caf26c4 | c426af1c | 8d1a93efeff4e52b993023ff5fe4258f |
| 2 | 1790341510 | dbeb2fa5 | a52febdb | c9eaebf976be1db9a3c0dedd60a45580 |
| 3 | 1790341511 | f619dd80 | 80dd19f6 | 7c0f16bdf580fe40ffbdd814d9e91740 |
| 4 | 1790341512 | d9af1ea8 | a81eafd9 | db59d7f63c55085aa493a55a09937b3f |
| 5 | 1790341513 | e9518d6e | 6e8d51e9 | f3bcaef7e77772d23b52258f6c0ffbd4 |

The F.py region reconstruction (HEAD_FIRST/HEAD_RESIGN) does **not** reproduce
these heads from the seeds. That is a property of the winning device, not the
decoder: testing `win_rows.json`'s memory-scanned (S, d0) pairs the same way
shows the winning process's d0 head-selector phase (and even its d4 source
halfwords) follow its own per-request process state — no selector byte in
0..255 maps `_d0_source(_d4_words(S))` onto the scanned d0 halfwords, in
either byte order. F.py's law was validated on the *test device's* corpus
(14/14, slice 147); it does not generalise to the winning device's process
state. The whitening decode itself is unaffected — the record, head, seed,
d2 and 32-B block are recovered exactly.

## 5. Is pure-Python synthesis now achievable?

| layer | status |
|---|---|
| Whitening decode (blob → record) | **pure Python, done** (`whiten_decoder.decode_blob`, ~20 ms) |
| Whitening encode (record → body) | **pure Python, done** (`whiten_forward`, byte-exact vs VM; replaces 30 s FinEx runs for remint checks) |
| Body synthesis (region → record) | pure Python, known (`body_decoder.py` layout + F.py laws); the only unpinned field is the 32-B block [46:78) — a hash of region words whose law is still inside FinEx |
| Digest words 40..47 | still VM-only (construction law not lifted; independent of the whitening) |
| Region entropy for a *new* signing | unchanged blocker: per-request head-selector phase + the winning device's own region derivation (§4c) |

So: the whitening is no longer a blocker for synthesis or decoding — any
captured blob can now be opened in 20 ms, and the encode half of a pure-Python
synthesiser is byte-exact. What remains VM-only is the digest section and the
32-B record block, and what remains device-bound is the region entropy.

## 6. Usage

```python
import whiten_decoder as W
dec = W.decode_blob(bytes.fromhex(blob_hex))     # 192-B signature
dec["record"]      # 144-B record (plaintext of blob[16:160))
dec["consts_ok"]   # all constant bytes + cert SHA-1 verified
dec["d2w"]         # decoded d2 descriptor word
dec["F_seed"]      # BE32(record[20:24)) — F.py native seed
dec["region"]      # (d0,d2,d4) via F.py laws, or None if the head phase
                   # is not one of the two known genuine phases
# low-level:
p = W.whiten_inverse(chunk16, WA16)              # one chunk
r = W.whiten_body_inverse(blob[16:160], blob[:16])
b = W.whiten_forward(record, header)
```

`python whiten_decoder.py` runs the full validation (trace round-trips take
~1 min; `--fast` skips them).

## 7. Side observations

* `_inv2_aff.gf2_solve`'s back-substitution can return a *wrong* (but
  self-consistent-looking) solution for under-determined pivot structures —
  fitting the rand trace alone produced a map with 208/468 mismatches. The
  real-trace map used here is verified directly on all 936 samples, so the
  embedded F is correct.
* `body_decoder.region_from` byteswaps the seed the wrong way
  (`_d4_words(LE32(rec[20:24)))` instead of `BE32`); its GF(2) decode is
  unaffected. The validated convention is in `whiten_decoder.region_from_record`.
