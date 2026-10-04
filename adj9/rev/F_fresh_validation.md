# F_fresh_validation — S-vs-V unification closed (2026-09-24)

Test of the hypothesis that the fresh-capture failure
(`SESSION_FINDINGS_SIGNATURE_GATE.md` §2d) is explained by a **pid term**
(`S_eff = S_urandom ^ (pid<<16)`) that the other session missed by calling
`region(S, 0)`.

Files: `F.py` (the complete pure-Python lift), `device/rows_full.json`
(fresh capture), `pair_h3.json` (8 old device rows), `adj9_tool/adj9_signer.py`
(the other session's signer, same materializer as `F.py`).

## VERDICT (headline)

**The pid hypothesis is REFUTED. The region is NOT fully offline-computable
from `(S, pid)` alone** — but the residual is *not* the seed or the Park–Miller
materializer. Precisely:

* `d2` and `d4[8]` are reproduced **byte-exactly** for every fresh row and
  every old row — the seed path is correct and `pid` contributes nothing.
* The ONLY mismatch is the first **2–3 words of `d0`** (the `post_x1`
  whitener-overwritten words). This is a **per-call runtime (scheduling)
  channel**, not a function of `S`. `F.py`'s fixed `post_x1` head
  `(0x22,0x2E,0x42,0x43,…)` was fitted to 8 old rows that happened to share
  one head; the fresh rows use a *different* head.

So: `region` is **not** a pure function of the seed, because of the `post_x1`
head. The other session's *conclusion* ("the region must be captured, not
computed") is **confirmed**, but their **diagnosis is wrong**: the seed is
pinned correctly (d2 matches), and the Park–Miller `d4` materializer is
faithful (8/8 fresh). The gap is the `d0` post-whitener head only.

---

## 1. Fresh capture located

`device/rows_full.json` (Sep 24 23:29), produced by
`device/foldhook_native.js` + `device/collect_spawn.py` (frida **spawn**,
`dev.spawn(["com.penti.app"])`), matched to blobs in
`device/nblob_179027271{1,2}.hex`. It is a genuine **device** capture with all
11 descriptors. Three sign rows:

| row | sign_id | second | tid | S (urandom) | d2 (raw bytes) |
|-----|---------|--------|-----|-------------|----------------|
| 0 | 1 | 1790272711 | 588 | `0x19d4c97e` | `7ec9d419` |
| 1 | 2 | 1790272711 | 581 | `0xe1c3efdd` | `ddefc3e1` |
| 2 | 3 | 1790272712 | 691 | `0x0f476009` | `0960470f` |

**Capture-process PID:** `collect_spawn.py` spawns the app and prints
`[spawn] spawned+resumed pid=…` to stdout, but that stdout was **not** saved
to a file for this run (no `pid` appears in any artifact). The per-row `tid`
(588/581/691) is recorded; the app `pid` is not recoverable from the stored
artifacts. This turns out to be **irrelevant** — see §2.

## 2. The pid term cannot be the cause (seed is pinned by d2)

`d2` is a bijective little-endian store of the native **seed**
(`F.region`: `d2 = int.from_bytes(seed.to_bytes(4,"little"),"big")`). So the
captured `d2` **uniquely determines the seed**. Recovering it:

| row | S (ctx) | seed recovered from d2 | equal? | d2-match pids ∈ {0,1,2,3,0x1111,0xFFFF} |
|-----|---------|------------------------|--------|--------------------------------------------|
| 0 | `0x19d4c97e` | `0x19d4c97e` | yes | **{0}** |
| 1 | `0xe1c3efdd` | `0xe1c3efdd` | yes | **{0}** |
| 2 | `0x0f476009` | `0x0f476009` | yes | **{0}** |

`seed = S ^ (pid<<16)`. For `d2` to match, `seed` must equal the recovered
value, which is exactly `S`; hence `pid & 0xFFFF` must be 0. Consequences:

* `region(S, pid)` reproduces `d2` **only at `pid=0`** (mod 2^16).
* The alternate composition `region(S ^ (pid<<16), 0)` for `pid != 0` changes
  `d2`, so it can **never** match the capture.
* Therefore **no `pid` value — neighborhood or otherwise — rescues the
  materialization**. The other session's `region(S,0)` call already used the
  correct, seed-pinned composition. Their `d0[0]=6a8fb857` vs captured
  `f92d6a8f` is reproduced here too, but it is **not** a `pid` bug.

## 3. Per-row result of `region(seed_from_d2, 0)` (pid term ≡ 0)

Region = 45 words = `d0[36] + d2[1] + d4[8]`.

| row | d2 | d4 | d0 | d0 diff words | region words matched |
|-----|----|----|----|----------------|----------------------|
| 0 | match | **8/8** | 34/36 | `[0, 1]` | 43/45 |
| 1 | match | **8/8** | 34/36 | `[0, 1]` | 43/45 |
| 2 | match | **8/8** | 33/36 | `[0, 1, 2]` | 42/45 |

`d4` is **perfect** on all fresh rows (the Park–Miller + Fisher–Yates +
transpose path is faithful for these seeds). `d2` is perfect. The mismatch is
confined to the low `d0` words.

Concrete `d0` deltas (captured vs `F.py` fixed-head):

```
row0  d0[0] cap=f92d6a8f got=6a8fb857    d0[1] cap=0d7eb857 got=f9df2f35
row1  d0[0] cap=872576bb got=76bb4a1b    d0[1] cap=fdc54a1b got=7fb9acc1
row2  d0[0] cap=ebbcb9c1 got=0ee70e69    d0[1] cap=0ee74d92 got=7ce69f1f
      d0[2] cap=0e693f93 got=da463f93
```

## 4. The 8 old `pair_h3` rows (current F.py) — 8/8 FULL

`region(seed_from_d2, 0)` against each old row's own captured d0/d2/d4:

| row | second | seed | d0 | d2 | d4 | result |
|-----|--------|------|----|----|----|--------|
| 0 | 1789239390 | `0xf516aa41` | ✓ | ✓ | ✓ | FULL |
| 1 | 1789239528 | `0x12b21e6b` | ✓ | ✓ | ✓ | FULL |
| 2 | 1789240075 | `0x94904031` | ✓ | ✓ | ✓ | FULL |
| 3 | 1789240076 | `0x4076156b` | ✓ | ✓ | ✓ | FULL |
| 4 | 1789240075 | `0xafcaca2e` | ✓ | ✓ | ✓ | FULL |
| 5 | 1789240228 | `0x985f5c11` | ✓ | ✓ | ✓ | FULL |
| 6 | 1789240340 | `0x6a896959` | ✓ | ✓ | ✓ | FULL |
| 7 | 1789240512 | `0x96821afb` | ✓ | ✓ | ✓ | FULL |

**8/8 full match** — because all 8 old signings share the *same* `post_x1`
head, the one `F.py` hard-codes. This is why the lift "validated 8/8 + 14/14":
those datasets never exercised a different head.

## 5. Residual isolated: the `post_x1` head is a per-call channel

`F._d0_words` overwrites the final twelve whitener outputs (words `d0[0..5]`)
with a fixed `post_x1` sequence. That sequence is a *runtime* input, not
derived from the seed. Given the (matching) `d4` → `source` halfwords, we can
invert the whitener and **recover the actual per-call x1 head**:

| row | recovered `post_x1` head (first values) | stable tail |
|-----|------------------------------------------|-------------|
| 0 | `0x2b, 0x22, 0x25, 0x2e` | `0x44 45 46 47 40 41 42 43` |
| 1 | `0x2b, 0x22, 0x25, 0x2e` | `0x44 45 46 47 40 41 42 43` |
| 2 | `0x2b, 0x07, 0x22, 0x25, 0x2e, 0x45` | `… 46 47 40 41 42 43` |
| old pair_h3 (all 8) | `0x22, 0x2e, 0x42, 0x43` | `0x44 45 46 47 40 41 42 43` |

The **tail `0x44,0x45,0x46,0x47,0x40,0x41,0x42,0x43` is fixed** across every
row; only the **head** (first 2–6 x1 values) varies per capture. Forward-
substituting the recovered head reproduces the captured `d0[0..1]` (and
`d0[2]` for row2) exactly, confirming the mechanism. The head changes even
between two signings in the *same app launch* one second apart (rows 0/1 at
second 1790272711 share a head; row2 at 1790272712 differs), so it is a genuine
**per-call thread-scheduling artifact** — the "second, hardware-real per-call
entropy channel besides V" documented in `fill_model.md` §7 and `F.py`'s own
"L3 device/emulator discrepancy" note.

Why `d0[0..1]` and not the tile phase: the tile words `d0[2..5]` and beyond
match **exactly** (the `d4`-derived source is right), so this is not a tile
phase rotation. It is specifically the `W0`/`X` head words the `post_x1`
overwrite.

## 6. Final verdict on offline region computability

* **NOT fully offline-computable from `(S, pid)`.** Given the seed (pinned by
  `d2`), `F.py` computes `d2` and `d4[8]` perfectly and 33–34 of 36 `d0`
  words, but the first 2–3 `d0` words depend on a per-call `post_x1` head
  that is not a function of `S`. So the region is **not** a pure function of
  the seed and cannot be regenerated offline for a target second.
* The pid composition is a **dead end** — refuted by the bijective `d2`
  (§2). `S` (urandom) is a valid seed and any 32-bit `S` yields a
  structurally-law-satisfying region, but the `d0` head bytes still differ
  from the device's, so a device-faithful blob cannot be minted offline from
  `S` alone.
* **The mint path does NOT open** via `S`. Practical consequences:
  - A *device-faithful* region still must be **captured per call** (the
    `post_x1` head is the irreducible residual) — confirming the other
    session's operative conclusion.
  - A *synthetic* region (any chosen `S` + any chosen head) still satisfies
    the structural laws (they depend on the matching tile words), so it is
    law-valid, but it is not byte-faithful to a device signing. Whether the
    server's booking gate accepts a synthetic head is a separate question,
    outside this unification.

### Correction to the other session
Their §2d claim "the region is not a faithful lift for all seeds → must be
captured" is **conclusion-correct but mechanism-wrong**. The seed and the
Park–Miller `d4` materializer are faithful for *all* tested seeds (3/3 fresh
`d4`, 8/8 old full). The only non-faithful part is the hard-coded `post_x1`
head in `F.py._d0_words`, which is a per-call constant that was over-fit to
one capture session. Fixing it requires capturing the per-call head (or
modelling the thread schedule), not a different `pid`/`S` composition.

## Reproduction (minimal)
```python
import json, struct, sys; sys.path.insert(0, "adj9/rev"); import F
rows = json.load(open("adj9/device/rows_full.json"))["rows"]
for r in rows:
    cap2 = bytes.fromhex(r["desc"]["2"]["hex"])
    seed = int.from_bytes(cap2, "little")          # d2 pins the seed
    d0, d2, d4 = F.region(seed, 0, 0)
    assert d2 == int.from_bytes(cap2, "big")        # always true
    assert d4 == [int.from_bytes(bytes.fromhex(r["desc"]["4"]["hex"])[i:i+4],"big")
                  for i in range(0,32,4)]           # always true (8/8)
    cap0 = [int.from_bytes(bytes.fromhex(r["desc"]["0"]["hex"])[i:i+4],"big")
            for i in range(0,144,4)]
    diff = [i for i in range(36) if cap0[i] != d0[i]]   # -> [0,1] or [0,1,2]
```
