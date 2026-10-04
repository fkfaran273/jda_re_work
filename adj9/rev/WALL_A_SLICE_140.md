---
title: WALL_A_SLICE_140
---

# SLICE 140 — region provenance closed: source buffer → copy loop → EMIT → VM

Date: 2026-09-21. The last open question (where the region comes from) is now
answered end-to-end with a live capture. Scripts: `rev/agent/appcap_reg_src.js`
(+ `_patch_reg4/5`), `rev/verify_reg5.py`. Artifacts: `rev/app_reg.json`,
`rev/app_signings5.json`, `rev/vreg5.log`.

## 0. The chain, measured live

The copy loop at `0x100150–0x100194` (inside the VM builder fn `0x100094`) reads each
descriptor from a **per-descriptor heap source buffer** and EMITs it (byte-swapped) into
the stream plane. Hooking `0x10017c` (`ldr w8,[x8,x22,lsl#2]`) captured the actual
source words this signing:

```
source buffer 0x6e0df46f40 (the #0 source), 36 words read:
  a2440fef a1f159f2 884a2ac3 f7ec0378 aed30c5a a1f125e1 884a2ac3 f7ec0378 ...
  (W0 then the tile, with the slice-139 low-half variant at the 2nd tile position)

  copy loop: rev32 each  ->  ef0f44a2 f259f1a1 c32a4a88 7803ecf7 5a0cd3ae ...
  EMIT stream 4115548080  ->  == this signing's #0 (captured, matches)
  VM reads it back via LENQ at 0xb400006ef54e47b0 (slots 0-4 match)
```

So: **source buffer (heap) → `rev32` → EMIT → descriptor stream → LENQ → blob.** Every
link now has a captured value. `#0` for this signing = `ef0f44a2…`, and the slice-129
bridge holds again (`R=9926`, `a[6]=(R<<16)|Xlo` ✓).

## 1. The 11 source buffers (one per descriptor)

The copy loop fires **11×** (`x23=0..10`), each with its own count cell
(`0x…52cc9…`) and source array. Read counts map exactly to descriptor sizes:
96≈#10 claims, **36=#0**, 8=#4, 5=#9, 4=#8, 1×4=#2/#5/#6/#7. The region's sources are
a cluster of heap buffers (`0x6e0df46…` family + one `0xb400007812cdc2d0`).

## 2. The final boundary (measured, not assumed)

The raw source words (`a2440fef…`, pre-`rev`) appear **nowhere** in the EMIT or LENQ
plane before the copy loop reads them — the source buffer was **written at process
init, before any attach can land**. This is the direct measurement behind the
"heap-state, not offline-derivable" conclusion: the region's entropy is generated
during the app's own startup, on memory that exists only in-process.

## 3. Status

* Verified corpus: **11 rows** (6 + app 127/137/138/139 + this), all exit-clean /
  byte-exact through FinEx. This row: sec 1789971572, steps 9889399.
* The region's *lifecycle* is fully mapped (init-generate → source buffers → copy loop
  → streams → blob). Its *values* remain per-process init-time entropy — capturable
  per signing via this exact pipeline, not computable offline.

## 4. Artifacts

* `rev/app_reg.json` (3.4 MB) — the source-read capture
* `rev/app_signings5.json`, `rev/verify_reg5.py` + `vreg5.log`
* `rev/agent/appcap_reg_src.js` + `appcap_reg.js` (500 KB; copy-loop + source-read +
  plane-retry hooks), `rev/agent/_patch_reg4.py`, `_patch_reg5.py`
