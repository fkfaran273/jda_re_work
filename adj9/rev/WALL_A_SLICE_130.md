---
title: WALL_A_SLICE_130
---

# SLICE 130 — entropy split: a[0..1] are structured, a[2..7]+tile+W0+d2 are random

## 0. Per-word entropy over all 11 rows (`rev/ent_probe.py`)

```
slot distinct popmean  xoravg  b0alpha
W0   11       17.4     31.1    11
T0   11       17.8     31.0    10
T1   11       16.5     30.8    11
T2   11       17.1     31.2    11
T3   11       16.5     31.2    11
d2   11       15.1     30.7    10
a0   11        2.4     23.4     4
a1   11        4.5     28.7     6
a2   11        6.6     30.4    10
a3   11        8.4     30.9    11
a4   11       10.5     30.7    11
a5   11       13.1     31.1    11
a6   11       14.5     31.0    10
a7   11       16.5     31.1    11
```

Random u32: popcount ~16, xor-width ~31, byte0 alphabet ~11/11.
Only a[0] (pop 2.4, xor 23.4, b0alpha 4) and partly a[1] (pop 4.5) deviate.
a[2..7] are statistically RANDOM words — no fold/XOR/ADD structure can ever
fit them (consistent with every 0-hit battery so far).

## 1. a[0]/a[1] internals (`rev/a01_probe.py`)

a[0] bits across rows: {1,15,17} {2,20} {0,25} {4,16} {1,2,18} {4,18}
{1,5,17} {10,20} {8,10,26} {7,20} {12,31}(app). LE-u16 views are small ints
(2..45056) but match no length/count in the signing. a[0],a[1] distinct
11/11 — even the structured words vary per signing.

## 2. a[2..7] as one 176-bit stream (`rev/a27bit_probe.py`)

Concatenated hex, consecutive-word deltas, same-offset byte reuse across
11 rows: deltas full-width, reuse at chance level (7 shared bytes over 24
offsets x 11 rows). No counter, no LCG, no keystream reuse — fresh random
per signing per offset.

## 3. R is not a half of H; region words are not small-int sources

`rev/collect_probe.py`: R (16-bit tag) appears in NO 16-bit half of H
(BE+LE, 6 clean rows: 0/6). No region word is within ±1 of
{R, R||R, claims_len, second, ts-low} (0/10 rows).

## 4. What this means (read carefully)

* The random words (W0, T0..T3, d2, a[2..7]) MUST come from a per-signing
  entropy source inside the builder. They are not derived from
  (claims, H, second) by any closed form — the batteries prove the negative
  exhaustively (PRNG streams, digests, HMACs, folds, H-slices, constant
  XOR/ADD/SUB incl. two-word expressions, time-lowbits, small-int sources).
* a[0..1] carry 2-5 bits each: plausibly version/flags/lengths — but also
  per-signing-distinct, so not pure constants.
* a[6] = (R<<16)|Xlo with R == Xhi^Xlo (slice 129, 11/11) is the ONLY exact
  relation in the whole region — one structured word out of fourteen.
* The remaining question is therefore NOT "what formula makes the region"
  but "what entropy source feeds the builder" — answerable only by reading
  `sub_9afa4`'s inputs (Path B) or a builder-memory capture (Path A ext).

## 5. Artifacts

* `rev/ent_probe.py`, `rev/a01_probe.py`, `rev/a27bit_probe.py`,
  `rev/collect_probe.py` (+ logs where kept)
* `rev/k02lo_probe.py` (K02lo battery: 0/11 vs 12 candidates)
* `rev/WALL_A_SLICE_129.md` §5 (a[6] fully solved, 11/11)
