# emu_replay — the 0x8d364 fault root-caused; the signing runs to the returned blob; the rand stream is bionic random() re-seeded per signing

Date: 2026-09-23. Harness `rev/emu_8d6f4.py` (fixed), debug drivers
`rev/dbg_replay.py` (repaired), `rev/dbg_x5.py`, `rev/dbg_watch.py`,
`rev/dbg_order.py`, analyzers `rev/analyze_blob.py`, `rev/seed_sweep.py`,
`rev/report_run.py`. Logs: `dbg_*_out.log`, `fix1..3_out.log`,
`report1/2.log`, `report_sec1/sec2.log`, `report_seedshift.log`.

## 0. Headline

1. **Root cause of the stable `[FAULT] access=19 addr=0xeb03378f1b88779
   pc=0x8d364`: the harness's `memset` PLT stub had its arguments swapped**
   (`bytes([x2&0xFF]) * x1` instead of `bytes([x1&0xFF]) * x2`). The builder's
   `memset(ctx, 0, 0x878)` at 0xfb50 (x0=ctx, x1=0, x2=0x878) therefore wrote
   **nothing**. Dead-frame junk survived in the ctx block: an early
   `sub_9afa4` call (a JNI `ExceptionOccurred` check; the O-LLVM state spill
   `stp x8, x19, [sp,#8]` at **0x9b02c**, frame aliasing the ctx area with
   sp = ctx+0x538) had spilled the junk marker 0x0eb03378f1b88779 exactly onto
   **haystack cell 0x4d = ctx+0x540**. The builder's anti-emulator string scan
   walks pointer cells `*(ctx + 0x70 + i*16)` sequentially (i = 0..0x4d, one
   `ldr x5,[x17,#0x70]` at 0x8d118 each), skips zero cells, and polls each
   non-null cell 24× (`ldrb w17,[x8]` at 0x8d364, case-insensitive byte compare
   against 24 decrypted needle strings: "Emulator", "AMIDuOS",
   "AndroidStudio", ... at 0x151d18+; the scan buffers include the in-place
   decrypted path string "/proc/net/tcp" at 0x151d08 and 0x13d88). Cell 0x4d
   (junk ≠ 0) was taken as a 5th scan buffer and dereferenced → fault. On
   device the memset zeroes the cell → skipped like the other 72 null cells.
2. With the one-line memset fix (plus supporting stub fixes, §2) **the full
   nSign → VM → sub_8d6f4 → wire-builder-VM → JNI-return path runs to
   completion** (~70 s, 1248 calls) and returns a real 208-B blob.
3. **Rand consumption observed: exactly 8 draws per signing**, return sites
   alternating **0x12a300 / 0x12a320** (the pair-XOR opcode's two `bl rand`;
   rand_path.md's token 0x2e6 @0x12a1f8), producing **4 pair-XOR units** stored
   big-endian at **wire offsets 0x00..0x0f = the blob's 16-B header**.
   `srand(time(NULL))` fires **inside the signing path** immediately before the
   draws (call order: … → `time` @0x12cbbc → `srand` → VM opcode
   `clock_gettime(CLOCK_MONOTONIC)` @0x18aa4 → 8× rand → SetByteArrayRegion).
4. **The rand implementation is bionic `random()` (BSD TYPE_3 additive
   feedback)** — NOT lrand48, NOT the ANSI LCG. With the harness switched to
   the TYPE_3 model ("random3") and the clock base set to a captured signing
   second, **the emulated blob header equals the device-captured header
   byte-for-byte**:
   * sec=1790106110 → `4efd72e6 33bbc54a 45c8e70f 10e63a5c` = signing 1 ✓
   * sec=1790106176 → `03bd3d9f 7fc91f7a 0c43c2f3 7e140f74` = signing 2 ✓
   (signing 3 verified at law level: `Random3(1790106196)` recomputes
   `3199cac6 753d466b 722eec0a 6f5ea925` exactly; seed = created_at second + 1.)
5. **Best (seed, impl, k) = (the signing's own second — e.g. 1790106110,
   `random3`/bionic random() TYPE_3, k = 0)** — the 8 draws are the FIRST 8
   after srand; there is **no pre-advance** and **no continuation across
   signings**: srand re-seeds per signing (Random3(sec2) draws 9..16 ≠
   signing-2 header; the three headers each invert uniquely to their own
   second). The requested sweep {1790106110±0..3} × {ansi, lrand48} × k
   (seed_sweep.py, k ≤ 500 000) produced **zero hits** for ansi/lrand48 and a
   clean 4/4-unit match for random3 at k=0.

## 1. Debug path (how the root cause was found)

1. `dbg_replay.py` (repaired — its `_dump_row` was never written) showed the
   poll ran **97 times in phases of exactly 24**, with the poll pointer x8
   walking ctx+0x808 → 0x151d08 → ctx+0x818 → 0x13d88 → junk, and a per-phase
   index i48 = 0..0x17; the junk entered register **x5** at hub pass #8453.
2. `dbg_x5.py` (x5 watch) + trail → the junk appears right after the block at
   0x8d0fc: `x17 = [sp+0x28] (= ctx); x17 += i50<<4; x5 = [x17,#0x70]` — the
   cell fetch; `cmp x5,#0; str (x5==0),[sp,#0x18]` — null cells divert before
   the poll, non-null cells poll.
3. `dbg_watch.py` (write watchpoint over the ctx block) found exactly one
   writer of ctx+0x540: **pc=0x9b02c**, plus the four good cells written by the
   0xde234-family arg spills (ctx+0x2d0/0x310/0x330/0x370 ← x1/x2/x0/x3 of a
   frame whose [sp] = ctx+0x2c8; the 16-B cells are {ptr, O-LLVM tag} pairs).
4. `dbg_order.py` (chronological interleaving): the junk write is event #249 —
   during the FIRST sub_9afa4 call, long before the cell writes (#1489-1500)
   and the scan (#1517+); nothing rewrites ctx+0x540 afterwards. Since the
   device's memset(ctx,0,0x878) must erase it, the memset stub was re-checked —
   and the argument swap found.

## 2. Harness fixes (all in `emu_8d6f4.py`)

| fix | why |
|---|---|
| `memset`: `bytes([x1&0xFF]) * x2` (was swapped) | **the root cause** — builder memset was a no-op; junk survived at cell 0x4d |
| heap bump allocator grows the mapping on demand (`heap_map_end`) | wire-builder VM's STORE/realloc-grew past the fixed 2 MB heap map (write fault at 0x53000240cac, pc=0x147040) |
| `realloc` copies old contents (size table `alloc_sz`) | the VM's STORE primitive realloc-grows the wire; without copy the wire self-corrupts |
| `SetByteArrayRegion`/`GetByteArrayRegion`: JNI args (env, arr, **start=x2, len=x3, buf=x4**) (was len=x2/buf=x3) | nSign returned a 208-B **all-zero** array (start=0 misread as len=0) |
| `rand`/`srand`: added `random3` = bionic `random()` TYPE_3 (31-word table, Park-Miller fill, 310 discarded, additive feedback f=3/b=0, output v>>1); default impl `random3`; fixed `lrand48`'s srand48 init (`(seed<<16)|0x330E`) | bionic `rand()` **is** `random()`; the header law (decode_signature.py `Random3`, proven 44/44) is TYPE_3 |

Driver repairs: `dbg_replay.py` gained the missing `_dump_row`.

## 3. What a completed run looks like (report_run.py)

* `stopped=returned`, ~70 s, 1248 calls (252 before the fix — the extra ~1000
  are the wire-builder VM's map.containsKey/NewStringUTF/put traffic).
* 104 property probes (2 more than before: `ro.build.version.release/sdk`).
* Final call shape around the draws: `NewStringUTF('10')`, `NewStringUTF('5.0.0')`
  (client_sdk version probes) → `time` → `srand` → `clock_gettime(CLOCK_MONOTONIC)`
  @0x18aa4 → 8× rand → `SetByteArrayRegion(start=0, len=208)` → map.put
  (`headers_id` → `10`).
* Draws for signing 1 (srand 1790106110): 751271802, 1647971740, 1082345470,
  1933083316, 1281939145, 161493446, 366984179, 87654831 — identical to
  `Random3(1790106110)` draws 1-8; units `4efd72e6 33bbc54a 45c8e70f 10e63a5c`.
* Draws for signing 2 (srand 1790106176): 940933, 62088730, 1020394168,
  1125705154, 517803597, 312396990, 1061680694, 1096022338 → units
  `03bd3d9f 7fc91f7a 0c43c2f3 7e140f74`.

## 4. Blob structure and the corrections it forces

* Emulated wire = **16-B header (the 4 rand pair-XOR units, BE) + body**.
  The device's 192-B captured blob = 16-B header + 176-B body; our run's body
  is 192 B because the synthetic cfg inputs (map values, H, cert, claims)
  differ from the device signing's — body length is input-dependent. The
  corpus statement "the wire body contains no descriptors" holds for our run
  too (#8/#9 anchor patterns absent from the wire).
* **WALL 146 §0/§5b correction**: the rand stream **IS re-seeded per signing**
  (`srand(time(NULL))` inside the signing path, not only at nOnResume); the
  "same-second signings draw different values" inference is void — the
  per-call body variation must instead come from the fine clock /
  per-call state (B1~B2: identical headers with identical second+map+H, bodies
  differing 175/176). The wire header itself is a **pure function of the
  second**: `srand(sec) → random() draws 1..8 → pairwise XOR → 4× BE u32`.
* **emu_findings §4 refinement**: the fine clock is real but is not the whole
  story — the header (and per the seed-shift experiment `report_seedshift.log`,
  where changing ONLY the srand seed moves the whole body) the rand stream
  whitens the entire wire; the CLOCK_MONOTONIC ns read at 0x18aa4 co-determines
  the per-call body where the second alone cannot (B1~B2). Offline minting of
  the **header** is fully solved (`Random3(second)`); the body needs the
  rand-stream mix (reproducible: seed = request second) plus whatever per-call
  state B1~B2 exposed — the next open question.
* The "5th haystack" anti-emu scan (cells 0x26/0x2a/0x2c/0x30 = ctx+0x808,
  "/proc/net/tcp", ctx+0x818, 0x13d88; needles "Emulator"/"AMIDuOS"/
  "AndroidStudio"/… × 24) found **no needle match** in our run — consistent
  with a clean device; the scan's outcome feeds the flow but the header law
  above is independent of it.

## 5. Reproduction

```
python adj9/rev/report_run.py --vary '{"sec":1790106110,"time_sec":1790106110}'
    # blob[0:16] == 4efd72e6 33bbc54a 45c8e70f 10e63a5c  (device signing 1)
python adj9/rev/report_run.py --vary '{"sec":1790106176,"time_sec":1790106176}'
    # blob[0:16] == 03bd3d9f 7fc91f7a 0c43c2f3 7e140f74  (device signing 2)
python adj9/rev/seed_sweep.py 20000 3 3      # sweep: random3 hits k=0; others none
python adj9/rev/dbg_order.py                 # root-cause trace (ctx events)
```
