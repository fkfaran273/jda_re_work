---
title: WALL_A_SLICE_124
---

# SLICE 124 — the builder is recursive, and its block write is a keyed XOR

## 0. Full dump obtained (the previous analysis was on a truncated file)

`s9afa4_full.log` turned out to hold only **222 lines**, not the 3072 instructions claimed —
and `dump_fn.py`'s prologue walk-back again landed on the **previous** function
(`0x9ad58`, size 0x254), the same addressing bug noted in slice 117. A direct disassembler was
added (`rev/dump_at.py`, dumps an exact VA + count) and produced the real body:

```
python rev/dump_at.py 0x9afa4 3072   -> 3072 instructions: 32 eor, 4 str q, 21 bl
```

## 1. What the builder does (structure, now visible)

* **`sub_9afa4` is recursive** — 9 of its 21 calls are `bl #0x9afa4` (plus `bl 0x9ad54`,
  `bl 0x9c724`, `bl 0x148b90`, `bl 0x1483e0`); it is a tree walker, not straight-line code.
* The **16-byte block write is a XOR of four words with ONE key register**, then a vector
  XOR, then a 16-byte store:

```
0x9bea4  eor w8, w8, w22       0x9cef8  eor w8, w8, w13
0x9beac  eor w9, w9, w22       0x9cf00  eor w9, w9, w13
0x9bebc  eor w8, w10, w22      0x9cf08  eor w10, w10, w13
0x9bec4  eor w9, w11, w22      0x9cf10  eor w8, w11, w13
0x9bef0  eor v0.16b, v0.16b, v1.16b
0x9bf08  str q0, [x30]         0x9cfc0  eor v0.16b, v0.16b, v2.16b
                               0x9cfc4  eor v1.8b, v1.8b, v8.8b
                               0x9cfc8  str q0, [x8]
                               0x9cfcc  str d1, [x8, #0x10]
```

* The key registers (`w22`, `w13`, `w15`, …) are the low words of the **64-bit constants
  assembled with `mov`/`movk` pairs** at the top of the function (e.g. `0xfa1e_a04f_5ea3_…`) —
  i.e. a per-site keystream table.

So each descriptor block is `src ^ key`, with `src` produced by the recursive walk.

## 2. It is still not an H function — extended search, 0 hits

`rev/const_diff2.py` generalises slice-123 §11 to **14 unknowns × 96 expressions**
(single `H` word, byte-reversed, rotations by 8/16/24, XOR of two, ADD of two):

| test | result |
|---|---|
| `X = E ^ K` with constant `K`, over all unknowns × expressions | **0 hits** |
| `X == E` (i.e. `K = 0`) | **0 hits** |

⇒ `W0`, the tile, `#2` and `#4`'s words are **not** one- or two-word `H` expressions under
XOR/ADD/rotate. Combined with the structure above, they are the **recursive builder's output**
(and/or state it walks), which is why every "is it a transform of X" probe has failed.

## 3. Status and what is left

* the *shape* of the computation is now known (recursive walk → keyed XOR blocks → 16-byte
  stores), so Path B is a concrete reduction of `sub_9afa4` rather than a black box;
* the *inputs* it walks are still unidentified, and the fastest way to pin them is Path A
  (capture the app's own signing, whose descriptor plane is complete — our own mint lacks
  `#9`, slice 122);
* the device is currently **offline over USB** (after the reboot the host never saw it
  again), so Path A needs a physical reconnect before `device/appcap_run.py` can run.

## 4. Artifacts

- `rev/dump_at.py` — exact-VA disassembler (fixes `dump_fn.py`'s walk-back bug)
- `rev/fn_9afa4_full.log` — the real 3072-instruction body
- `rev/const_diff2.py` + `const_diff2.log` — extended constant-relationship search
- `rev/WALL_A_SLICE_123.md` §11, `rev/REMAINING_WORK.md` — context and handoff