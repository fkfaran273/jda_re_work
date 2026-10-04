# Wall A — slice 104: `#4`/`#2` are per-call process state (not derivable), and the maker's `#4` defect is FIXED

Date: 2026-09-18. Scripts: `rev/h4_analyze.py`, `rev/forge_d4_test.py`; patch in
`rev/adj9_forge.py`.

## 0. Headline

Two results, one measurement and one fix:

1. **`#4` and `#2` are not functions of the material we know.** Two signings with
   the **same claims and the same second** still produce different `#4` *and*
   different `#2`. Since the server cannot recompute `#0`/`#2`/`#4`, it cannot
   recompute the body at all.
2. **The maker was filling slot `#4` with a MAC.** `adj9_material.json` has
   `H_policy = "random 32B per call"`, `captured_H` = two uniform MACs, and **no
   slot 4 entry** — so `make_signature()` wrote a MAC (or random bytes) into the
   structured `#4` slot. **Patched and regression-tested (PASS).**

## 1. Determinism — measured (`h4_analyze.log`)

`desc_det_result` holds three signings from one session with recorded
`created_at` + `sec`. Two of them (index 0 and 2) have **identical** `created_at`,
**identical** `sec 1789240512`, and **identical 360-byte claims**:

```
sec=1789240512  claims_len=360  n=3  claims_identical=True
    golden  d4=00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e  d2=fb1a8296
    det[0]  d4=00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e  d2=fb1a8296
    det[2]  d4=0010008000b000a82098003c08000a9820958aa10a3e04b0205f123f5e3c5feb  d2=4bce691e
    => #4 distinct: 2/3   #2 distinct: 2/3
```

This is exactly the configuration slice 99 §6 listed as *still missing* ("two
signings in the same second with the same map") — it was sitting in
`desc_det_result.json` all along.

**Consequence:** `#4` and `#2` come from per-call process state (allocation
order / PRNG / stack), not from anything the request or the claims determine.

## 2. The harvest is nevertheless exact

The same signing appears in **three independent harvests** and yields a
byte-identical `#4`:

```
golden == det[0] == als[7]  ->  00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e
det[2]  == als[9]           ->  0010008000b000a82098003c08000a9820958aa10a3e04b0205f123f5e3c5feb
```

So the values are reproducible *for a given signing*; only cross-signing
determinism fails.

## 3. Structure of `#4` (`h4_analyze.log`)

```
bytes   : 00 10 04 00 04 14 40 00 80 00 c4 40 88 10 4c 05 00 25 c8 52 cc 6e 00 b1 01 e7 6c 80 42 7b f5 8e
popcount:  0  1  1  0  1  2  1  0  1  0  3  1  2  1  3  2  0  3  3  3  4  5  0  4  1  6  4  1  2  6  6  4
```

Bit density **rises left→right** (0 → 6 ones/byte); a MAC/hash is flat ~4/byte.
Per-dword popcount for the golden is `[2,4,5,8,9,13,12,18]` (71/256 bits). No
simple transform of a captured H matches it, and no digest of the signing's own
material matches it (slice 103), so it is a *record* produced by the native
signing path (allocation-tied) — the byte-0 alphabet `{00,02,04}` and the
monotone density are the remaining clues for a derivation.

## 4. The maker defect and the fix

Found:

```
adj9_material.json:  slots = {9,8,2,7,5,1,6,3}          # no 4, no 0
                     H_policy  = "random 32B per call"
                     captured_H = {sess_H: 46cb9a96…, click_H: 732c4289…}   # uniform MACs
adj9_forge.make_signature():  h = H if H is not None else secrets.token_bytes(32)
                              by[4] = (8, h)             # <-- MAC/random into #4
```

Measured effect (`h4_vs_H.log`): `#4 = captured structured record` → blob
`== golden` (48/48); `#4 = the real H` → `diff = 44/48`. So every arm that used
`make_signature()` (or `HRAND=True`, or `--H`/borrowed-H) shipped a blob whose
`#4` slot could not match a device blob.

Fixed in `rev/adj9_forge.py`:

* module-level `CAPTURED_D4` loaded from `fin_descs.json` (`build_idx 4`);
* `make_signature(..., d4=None)` now writes the captured record and returns it;
  a passed `H` is **ignored with a warning** ("`#4` is not H");
* `make_signature_map(..., d4=...)` prefers an explicit `d4`, then the legacy
  `h_input` alias, then the captured template; `H` ignored with a warning;
* both return `d4` instead of a misleading `h`.

`adj9_full_chain.make_signature` was already correct by default (it takes every
descriptor from `fin_descs`, so `by[4]` is the captured record) — only its
`HRAND=True` flag corrupts the slot, and that flag should now be treated as
invalid for `#4`.

**Regression test (`forge_d4_test.log`) — `=== RESULT: PASS ===`:**

```
1. CAPTURED_D4 == the golden structured #4 : True
2. make_signature() default : status=exit-clean  law=True  d4=<captured record>
3. make_signature(H=REAL_H) : warns, ignores H, d4=<captured record>, blob exit-clean
4. make_signature_map default : returns the captured record
```

## 5. What this closes and what it opens

**Closes:** `#0`, `#2`, `#4` are all per-call state (`#0` = heap/MTE pointers per
slice 85; `#2`/`#4` per §1). None of them is computable from the request, and the
server cannot recompute them either ⇒ **the server cannot recompute the body**,
so any signature gate it applies must be a comparison against bytes it already
holds from the app. This is now supported by an independent argument, not only by
the `dev_ab` asymmetry.

**Prediction to test** (the OPEN item in `adj9/TASKS.md`): a fresh device-mint of
our map, sent immediately with a byte-exact claim set, should still read
**Organic** — because those exact bytes were never transmitted by the app. If it
instead books, the model is wrong and the signer is the gate.

**Opens:** `#4` is the only still-unexplained input. Its monotone bit-density
profile is a real lead (a shaped record, not entropy), and `#2` correlates with
it (both differ in the same-second pair), which hints they are two views of one
per-call context record.

## 6. `#2` vs `#4`: not derivable from each other, and they move together

`rev/h24_rel.py` → `rev/h24_rel.log` (14 samples: `fin_descs` + the 3
`desc_det_result` signings + the 10 `all_signings`).

**(a) `#2` is not a function of `#4`** — nine candidates, 0/14 each:

```
crc32(d4)  adler32(d4)  fnv1a(d4)  sum(dwords)  xor(dwords)  dw0  dw1  dw7  popcount(d4)
all 0 / 14
```

**(b) `#0`, `#2` and `#4` co-vary perfectly.** Across all 91 pairwise comparisons
the three slots are never decoupled: wherever `#4` is equal, `#2` and `#0` are
equal too, and wherever `#4` differs, `#2` and `#0` differ too
(`-> consistent (all three move together)` on 91/91). Combined with slice 85
(`#0` = heap/MTE pointers) this is what "one per-call context record with three
descriptor views" looks like — `#4` is simply the widest view of it.

**(c) The `#4` head is a sparse per-call bit-field.** Reading the first 8 bytes as
64 bits, 5–8 bits are set and **no bit is constant across samples**:

```
golden 0010040004144000 -> {11, 21, 37, 43, 45, 49}
det[1] 0400050080008440 -> {5, 21, 23, 32, 48, 53, 57}
det[2] 0010008000b000a8 -> {11, 24, 40, 42, 43, 56, 58, 60}
als[0] 00028002800a4008 -> {14, 16, 30, 32, 44, 46, 49, 60}
als[3] 0001001000300025 -> {15, 27, 42, 43, 58, 61, 63}
```

So the head is **not** a key/algorithm/context id (those would repeat); it is
per-call state, consistent with §1 and with `#0` being addresses. This retires
the last "maybe it is a constant identifier" hypothesis for `#4`.