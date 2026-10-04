---
title: WALL_A_SLICE_129
---

# SLICE 129 — d0's tile law + the d4[6] bridge (11/11)

## 0. Raw finding (offline, `all_signings.json` + `app_signings.json`)

d0 is 36 words: `[W0][T0 T1 T2 T3] x8 + W0` — i.e. W0, then an 8x repeat of a
4-word tile, then W0 again (row 9: same shape with a 5-word pre-amble
`f1a55b5b 9949bda6 | [337d5f21 011d4d1e 13227bce 21426d41] x8 + tail`).

Per row, with `K02 = T2^T0`, `K13 = T3^T1`:

```
K13 = R||R   (R = 16-bit row tag; 11/11 rows incl. app)
K02hi == R   (10/11; row 9 uses its second tile candidate, then 11/11)
```

R per row: `1962 324e 8e67 60f2 12ed 602b 5a36 01e7 a290 205f cc61(app)`.
R appears NOWHERE else: not in W0's halves, not in any tile half, not in H
(bytes), not in claims, not in the blob, not in second-low16 (all 0/11).

## 1. The bridge: d4[6] carries R (11/11, exact)

```
i  R     #4[6]      #4[6]hi==R
0  1962  196213d7   True
1  324e  324eac74   True
2  8e67  8e67625a   True
3  60f2  60f22dc0   True
4  12ed  12ed3236   True
5  602b  602b0eec   True
6  5a36  5a362d6e   True
7  01e7  01e76c80   True
8  a290  a2906389   True
9  205f  205f123f   True
app cc61 cc6183f8   True
```

And one step further — with `X = T0^T1`:

```
(a6lo ^ R) == Xhi    11/11 (rows 0-8 + row-9-canonical + app)
```

i.e. `#4[6] = (R << 16) | (Xhi ^ R)`. The d0-tile and d4 are the SAME
keystream family: the tile's tag R is stamped into d4[6]'s high half, and
d4[6]'s low half is the tile's own first-step high half with R folded out.

## 2. What this kills and what it leaves

* Kills: "tile words are independent unknowns" — the tile is 2 base values
  + one 16-bit R (T1 = T3^R||R, T2 = T0^(R||Xlo-part)). Effective d0 unknown
  drops from 20 B toward ~10 B + R.
* Kills: "d4 is an independent 32 B record" — d4[6] is DERIVED from the
  d0 tile (R + Xhi). d4's 8 words are not 8 independent unknowns.
* Leaves open: W0 (no half equals R, no R||R relation; R16 absent from H),
  #2 (not an a-word, not an a-word^R||R; halves share only chance bits
  with R), d4[0..5,7], tile base values T0/T1.

## 3. Next (concrete, offline-first)

1. Extend the bridge: test every d4 word's halves against (R, Xhi, Xlo) and
   W0's halves — d4[7]/d4[5] next; then #2's halves against the same set.
2. Fold R into the builder reduction: `sub_9afa4` writes 16-byte blocks as
   `4 words ^ ONE key register`; R||R-shaped keys should be visible at the
   block-write sites in `fn_9afa4_full.log`.
3. Re-run const_diff batteries with canonical tiles + R as an explicit
   input column (prior runs used raw words and could not see tag relations).

## 5. d4bridge2 extension (this session): a[6] is FULLY solved (11/11)

`rev/d4bridge2.py` tested every d4 word's halves against
{R, Xhi, Xlo, W0hi, W0lo, d2hi, d2lo, Xhi^R, Xlo^R, Xhi^Xlo}:

```
a[6]hi == R        11/11
a[6]lo == Xlo      11/11
a[6]lo == Xhi^R    11/11   (same fact: Xlo == Xhi^R)
a[6]hi == Xhi^Xlo  11/11   (same fact: R == Xhi^Xlo)
```

So `a[6] = (R << 16) | Xlo` with the constraint `R == Xhi ^ Xlo` — i.e.
**K13's high half equals the xor of the two halves of T0^T1**. a[0..5,7]
and #2 show NO half-equality (0/11) against any of the 10 candidates, so
the bridge is exactly one word wide. The remaining d4 words + #2 + W0 +
tile bases are still unsolved — but any candidate rule must now also
satisfy the `R == Xhi ^ Xlo` constraint, which is a sharp filter.

## 6. Artifacts

* `rev/xhi_probe.py` (+ fixed pair_h3 KeyError guard) — R-absence battery
* `rev/constx_probe.py` — pairwise-XOR bit-lengths (#4[0] avg 23.4 vs ~31
  elsewhere: the sparse-bitfield slot), claims_len-XOR battery
* `rev/tilewalk_probe.py`, `rev/hseed_probe.py` (H-seed PRNG: 0 hits),
  `rev/lcg_probe.py` (time-lowbits/LCG tables: no hits)
* `pair_h3.json` (6 clean rows), `app_signings.json` (11th row)
