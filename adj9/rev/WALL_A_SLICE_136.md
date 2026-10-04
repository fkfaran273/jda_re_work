---
title: WALL_A_SLICE_136
---

# SLICE 136 — the pairing gate opens: 6/8 rows verified BYTE-EXACT through the VM

Date: 2026-09-20 (late session). All offline. Scripts: `rev/sign56.py`, `rev/tile13.py`,
`rev/bodymatch.py`, `rev/pair_fix.py`, `rev/invertpair.py` (per-row runs),
`rev/verifypairs.py` (+ `verifypairs.log`), `rev/ks_table2.py` (+ `ks_consts2.json`),
`rev/ks_wedge.py`, `device/secdrift_run.py`.

## 0. Headline

The `(row → blob → second)` pairing that `REMAINING_WORK.md` calls **the gate for the
whole derivation** is now open on **6 sound rows**:

```
pair i=0 d2=41aa16f5 sec=1789239390 BYTE-EXACT  (steps 10493669)
pair i=1 d2=6b1eb212 sec=1789239528 BYTE-EXACT  (steps 10493669)
pair i=4 d2=2ecacaaf sec=1789240075 BYTE-EXACT  (steps 9871985)
pair i=5 d2=115c5f98 sec=1789240228 BYTE-EXACT  (steps 9871985)
pair i=6 d2=5969896a sec=1789240340 BYTE-EXACT  (steps 9871985)
pair i=7 d2=fb1a8296 sec=1789240512 BYTE-EXACT  (steps 9871985)
MISMATCHES: 2 / 8   (rows 2 and 3 only)
```

i.e. for rows 0/1/4/5/6/7 the offline VM takes the **captured descriptors + the claimed
second** and reproduces the **claimed wire blob 48/48**. Pairing, descriptors and the VM
are mutually consistent on 6 independent signings (3 capture batches).

## 1. What it took (three corrections, all measured)

1. **Header inversion per row** (`invertpair.py`): `pair_h3.json` seconds were off by
   −1/−2 s on most rows (the original pairing used the *map's* `created_at` window, not
   the blob's own header). Each blob's header was inverted against `make_header` and the
   corrected second written back:
   `i=0 −1, i=1 −2, i=2 −1, i=4 −1, i=5 −1, i=7 −2` s.
2. **`bodymatch.py` settled the second-independence question: FALSE.** Same descriptors
   at two far-apart seconds give **different bodies** (`bodyA == bodyB: False`). The
   descriptor-only shortcut is dead; the **second enters the VM** (via the OP_RAND
   draws consumed during the merge — consistent with the header law living inside the
   same walk), so verification must be per-second. That is what `verifypairs.py` does.
3. **Per-second FinEx verification** (`verifypairs.py`): for each pair row, locate the
   `all_signings` row by `d2`, run FinEx at the corrected second, compare all 48 words
   to the claimed blob. Result above.

## 2. Rows 2/3: diagnosed, fix in flight — CLOSED (no ground truth exists)

* Rows 2 and 4 were both paired to the **same blob** (`211c2cd4…`, ts 1789240076148) —
  row 4 verifies BYTE-EXACT, so that blob belongs to row 4's descriptors; **row 2's
  true blob is a different one**.
* Root cause: rows 2/3 come from `whcap_hits3.json` (created_at 2026-09-12T21:03:20),
  whose companion log should have been `adj9_wh3.log` — **that file is 0 bytes**.
* `find23.py` harvested **every** blob from `adj9_wh.log` + `adj9_wh2.log` +
  `adj9_wh4.log` (382+386+16 records → **201 distinct blobs**, `blob_pool.json`),
  inverted all 200 invertible headers, and checked the timeline: **the nearest pool
  blob is 268 s away from rows 2/3's signing second** (1789239800). The 21:03:20
  signings were never written to any log.
* FinEx arms against the nearest candidates (sec 1789240075 / 1789240076): **no match**
  (expected — those are the 360 B session blobs; rows 2/3 are 504/532 B push_token
  variants).
* **Conclusion: rows 2/3 are unverifiable, not failed** — the corpus offers no ground
  truth for them. The verified set is **6/6 rows where a blob exists** (0,1,4,5,6,7),
  plus the app row (slice 127). For any fitting work, use those 6; rows 2/3's
  `(H, second)` remain unknown.
* Note the H-column is irrelevant to this test: H is not a blob input (slice 103);
  `verifypairs` uses only `d0/d2/d4/d7/d8/d9/d10 + second`.

## 3. Builder-side progress (Path B, static)

* `ks_table2.py` → `ks_consts2.json`: full keyed-XOR census of `sub_9afa4`
  (3072 insns, 32 `eor`, 103 stores). **Four key registers carry exactly four 32-bit
  constants**, each used at a cluster of eor sites:
  `w22=04a01471` (5 sites @0x9be..), `w13=4138933c` (9 sites @0x9ce../0x9dd..),
  `w15=c3962f9c` (7 sites @0x9d3..), `w12=da71c6bd` (4 sites @0x9df..).
  This matches slice 129's tile algebra shape (`K02`, `K13 = R||R`) — the per-site
  keystream table is now enumerated, not inferred.
* `tile13.py`: per-sample tile structure re-verified (prefix=1, period=4, tile ×8) and
  the row-9 6-distinct-word case explained (5-word preamble + shifted tile); no new
  cross-row relations ("relations: none" on all rows — R stays per-signing).
* `ks_wedge.py`: wedge points between the recursive walker and the keyed store sites
  (for a future runtime patch/mirror experiment).

## 4. Device side

* `secdrift_run.py` (capture signings at controlled clock offsets to measure the
  second's entry into the body) — **failed: `[fatal] no attach`** (the app's attach
  latch again; runbook fix = reboot + attach-after-reboot).
* Device still enumerates over ADB (`ZD2228MY3X device`); fs/app attach needs the
  reboot ritual before the next capture.

## 5. Standing state after this slice

| item | state |
|---|---|
| verified `(H, second, claims) → #0/#2/#4` rows | **6** (0,1,4,5,6,7) + app row (127) |
| VM reproduction at true second | 48/48 on all 6 + 2/2 app arms |
| body second-dependence | **proven** (bodymatch step 0) |
| rows 2/3 | blob reassignment in flight (wh3 log empty) |
| region derivation (offline formula) | **closed as impossible** (slice 131: heap-object inputs) |
| only fresh-byte route | Path A-ext builder-memory capture (needs rebooted attach) |

## 6. Artifacts

* `rev/verifypairs.py` + `verifypairs.log` (6/8 BYTE-EXACT)
* `rev/invertpair.py` + `invertpair{0,1,2,4,5,7}.log`, `rev/pair_fix.py`,
  `rev/fixpairs.py`, `rev/checkpairs.py`, corrected `rev/pair_h3.json`
* `rev/bodymatch.py` + `bodymatch.log` (second-dependence proof)
* `rev/ks_table2.py` + `ks_consts2.json` (4 key registers, 25 keyed eor sites)
* `rev/tile13.py` + `tile13.log`, `rev/sign56.py`, `rev/ks_wedge.py`
* `device/secdrift_run.py` + `secdrift.log` (attach failure, recorded)
