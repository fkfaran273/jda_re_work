---
title: WALL_A_SLICE_128
---

# SLICE 128 — the fit closes on what the region is NOT (and what pairing is)

## 1. `h4fit`: no keyed digest of `H` makes `#4`

Anti-pairing failure first: the widened `pair_h2.json` put rows **before** their own
`created_at` by up to 594 s (e.g. row 0: `ws=1789239390` vs `sec=1789239071`, `d=-319`),
so any conclusion drawn from it is invalid. `h4fit.py` works only on the 6 clean rows
(0,1,4,5,6,7: `pair_h3.json`, all with distinct `H` — 6/6, so an `(H,second)`-only function
cannot be ruled out by uniqueness):

```
distinct H: 6/6
[0] none [1] none [4] none [5] none [6] none [7] none
total hits: 0
```

Tested: HMAC-SHA256(H,claims), (H,claims+sec), (claims,H), (H,sec); HMAC-SHA1(H,claims);
sha256/sha1/md5/blake2s of H by itself (BE windows and the reversed LE view); H's LE
and BE words xor-folded to 8 words. **0 hits.** A follow-on check also showed `#9` is not
sha256/sha1/md5/blake2s of `H`, `H[:20]`, or `H[12:32]` on any of the 8 paired rows — so
even the session-constant `#9` is digest-unrelated to per-signing `H`.

## 2. `uniq_probe`: collision structure across 11 rows (10 + app)

Instrument notes: all 11 region components are distinct (`d0=11 d2=11 d4=11`) — with a
standout honest detail:

* rows **7 and 9 carry byte-identical 360-B claims** (`7b8a23c8…` both) yet completely
  different `#0/#2/#4`;
* the new **app** row (its own fresh signing, `second=1789903463`) is the 11th distinct
  component everywhere.

That is the excluded-middle result: **same claims ≠ same region**, so no claims-only
function (folds, digests, layout encodings) can ever fit — and same for `created_at`.

## 3. Booking form, for the records

The remaining admissible inputs are still only (`H`, `second`) — both per-signing, both
now available with sound pairing. The negative table this now closes:

| family | evidence |
|---|---|
| claims folds / layout / digests / lengths | slice 126 + slice 127 §6 + this slice's 7/9 pair |
| `Random3(second)` output and xor-pairs | slice 123 §8 |
| seeded-from-`W0` streams | slice 123 §8 |
| checksums of claims/#0/#4, `#2` as slice of them | slice 123 (`d2_probe`) |
| `#0`/#2/#4 as transforms of `H` | slices 123 §9/§11 |
| `#2` as keyed digests of (H,claims,second) | this slice (`h4fit` covers `#4`; `#2` battery in slice 123 §11 and here) |
| constant XOR/ADD/SUB relations, single or two-word, and among the unknowns | slice 123 (`const_diff`), slice 124 (`const_diff2/3`) |
| consumed-but-constant slots explained away | slice 127 §5 (`#9`-zeros/`#8`-zeros ablations) |

## 4. Artifacts

- `rev/h4fit.py` + `h4fit.log` (6 clean rows, 0 hits)
- `rev/uniq_probe.py` + `uniq_probe.log` (11-row collision map)
- `rev/pair_h3.json` (sound dataset), `rev/app_signings.json` (app row)
- `rev/WALL_A_SLICE_127.md` (app's own signing, 2/2 BYTE-EXACT)