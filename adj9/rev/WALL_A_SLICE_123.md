---
title: WALL_A_SLICE_123
---

# SLICE 123 — the unknown collapses to 56 bytes per signing

All results below are **offline**, from the 10 real signings in `rev/all_signings.json`
(complete descriptor sets captured from the app's own signings), so they do not depend on
the device being reachable.

## 1. Four descriptors are CONSTANTS

| slot | distinct values over 10 signings | value |
|---|---|---|
| `#9` | **1** | `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` (20 B) |
| `#8` | **1** | `bffffffffffffd1f0007000000000000` (16 B) |
| `#5` | **1** | `00000000` |
| `#6` | **1** | `00000000` |

⇒ they can simply be **hardcoded** in an offline signer. (`rev/desc_const.py`, `desc_const.log`)

## 2. Two descriptors are already computed offline

* `#7` = **unpadded claims length** — verified against every sample:
  `502/504`, `529/532`, `360/360`, `387/388`;
* `#10` = the claims string (`desc10_law` builds it byte-exactly for session/click and by
  prediction for attribution/event).

## 3. `#0` is only 20 informative bytes

Across 9 of 10 samples: **36 words, 5 distinct** — `#0 = [W0] + [16-byte tile ×8]`
(period-4 matches 31/32, `reps=8`). Sample 9 has 6 distinct words (one extra).

```
[ 0] distinct=5  tile=['aeca29cb','a47f3a1c','b7a87905','bd1d237e']  W0=6ca93c67
[ 7] distinct=5  tile=['db50f44c','b63798cc','dab7f51a','b7d0992b']  W0=13271271
[ 9] distinct=6  tile=['9949bda6','011d4d1e','13227bce','21426d41']  W0=f1a55b5b
```

So the 144-byte descriptor carries `W0 | T0 T1 T2 T3` = **20 bytes** of information.
(`rev/d0_struct.py`, `d0_struct.log`)

## 4. What is left

```
per signing unknown = #0 (20 informative bytes) + #4 (32 bytes) + #2 (4 bytes) = 56 bytes
```

with `#4`'s leading word visibly a **sparse bitfield** (`00028002`, `00100004`, `02000001`,
`00010010`, `00040006`, `00040010`, `00020022`, `00100400`, `04000500`, `00100080`) and `#2`
a single high-entropy word that co-varies perfectly with `#0`/`#4` (slice 104: 91/91).

## 5. Negative result recorded

`#2` is **not** crc32 / adler32 / fnv1a / Java `hashCode` / md5 / sha1 / sha256 / blake2 of
`claims`, `#0`, `#4`, `d7`, or `#0`'s tile — **0 hits** over all 10 samples and several word
offsets/byte orders. (`rev/d2_probe.py`, `d2_probe.log`)

## 6. Device status and the tooling this round

* host capture is blocked again: `ptrace pokedata: I/O error` (the app latches; a **reboot**
  clears it — that was verified in slice 120);
* `frida-server` needs the **respawn loop** now shipped as `device/fsloop.sh`
  (single-instance starts get reaped even with the phantom-process killer disabled);
* the SDK **does not re-sign on a plain resume** (session throttle) → the app-capture agent
  gained a non-destructive in-memory nudge `Adjust.setSessionInterval(1)` +
  `setMinTimeBetweenSessions(1)` (`rev/agent/appcap_src.js`, `rpc.forceSession`), and
  `device/appcap_run.py` runs background/resume cycles against it.

## 7. Artifacts

- `rev/desc_const.py` + `desc_const.log` — constancy table
- `rev/d0_struct.py` + `d0_struct.log` — `#0` structure (5 distinct words)
- `rev/d2_probe.py` + `d2_probe.log` — `#2` digest battery (0 hits)
- `rev/agent/appcap_src.js` + `appcap.js`, `device/appcap_run.py` — app's-own-signing capture
- `device/fsloop.sh` — frida-server respawn loop
## 8. Two more negatives, and an important observation

Both tested offline over all 10 samples:

| hypothesis | test | result |
|---|---|---|
| `#0`'s 5 words are more draws of `Random3(second)` | raw `next()` **and** the header's xor-pair form, `created_at ± 5 s`, 6 000 draws each | **0 hits** (`rev/r3_desc.py`, `r3d.log`) |
| the 16-byte tile is generated **from `W0`** as seed | `Random3(W0)` / bionic `rand()` / `rand_r`, five seed variants (as-is, `&0x7fffffff`, `\|0x80000000`, byte-reversed, `^0xffffffff`), 4–8 k draws | **0 hits** (`rev/w0_seed.py`, `w0s.log`) |

**The observation that matters:** samples **7, 8, 9 share the same `created_at`
(`2026-09-12T21:15:11`) but have different `W0`/tile** —

```
[7] W0=13271271 tile=db50f44c b63798cc dab7f51a b7d0992b
[8] W0=aa447d3c tile=2ec65f51 efdf3cd8 8c568829 4d4f9e48
[9] W0=f1a55b5b tile=9949bda6 011d4d1e 13227bce 21426d41
```

So `#0` is **not** a function of (claims, second) alone — it varies with per-signing state
that the claims do not carry. That is consistent with slice 115 (same map + same second ⇒
identical `#0`, different second ⇒ different) and rules out any fit that only takes the
claims as input. Any derivation must consume the per-signing inputs the device has at call
time — i.e. **`H`** (available as `arg3` in `adj9_wh.log`, slice 112) and/or the signing
second, which is why the next fitting step requires pairing samples → `H` → second.

## 9. H-pairing: what works, what still needs a rule

`rev/pair_h.py` builds the `(claims, H, second)` dataset from the device's own log:

* record formats confirmed: `nsign` carries the blob `hex=…`, `nsign_in` carries
  `arg3_hex=…` (= `H`) 1 ms earlier;
* `adj9_wh4.log`: `nsign=8`, `nsign_in=9`, 8 distinct blob headers.

**Strict pairing (created_at ±1 s) works** for the samples that belong to that log —
samples 4–7 pair cleanly, e.g.

```
[7] ws=1789240511 second=1789240512 blob=5595c3c431567e63 H=eebe704e53a5cd3dad5fbf42cbb5ef96…
```

**Two rules remain, both mechanical:**

1. **per-source log** — each sample's `src` names its capture (`whcap_hits.json`, `hits2`,
   `hits3`, `hits4…hits7`), so pair against the matching `adj9_wh*.log`; samples 0–3 are not
   in `adj9_wh4.log`, which is exactly why a widened (±900 s) window mispaired them;
2. **order-preserving assignment for the shared-`created_at` group** — samples 7/8/9 all
   carry `created_at = 2026-09-12T21:15:11`, so a ±1 s window cannot separate them; assign
   the three nearest-in-time *distinct* blobs in capture order (three consecutive signings).

## 10. Pairing, second attempt: 10 rows with H — but only the strict subset is sound

`rev/pair_h2.py` scans the three big logs for the ~2 322 candidate header strings
(`make_header(ws-600..ws+600)`) and picks, per sample, the nearest **free** candidate, then
takes `H` from the nearest `nsign_in` within 10 s. Result: **10 rows, all 10 with `H`**,
saved as `pair_h2.json`.

But a direct comparison with the strict run exposes the flaw:

| sample | strict (±3 s) | widened (±600 s, nearest-free) |
|---|---|---|
| 4 | `sec=1789240075 blob=211c2cd4…` | `sec=1789239528 blob=5b71ec7c…` |
| 5 | `sec=1789240228 blob=505f30c7…` | `sec=1789240075 blob=211c2cd4…` |

⇒ the widened **proximity** rule re-assigns blobs that the strict rule had placed correctly:
it is **unsound** and `pair_h2.json` must not be used for fitting as-is. What it *did* add is
coverage: every sample now has a plausible `H` available, and the three logs are confirmed to
hold the relevant records (`candidate-header hits: 19`, `nsign_in records: 403`).

**Sound subset (strict, ±3 s, own log):** samples **0, 1, 4, 5, 6, 7** — each with
`second`, `blob` and `H` (e.g. `[7] second=1789240512 blob=5595c3c431567e63
H=eebe704e53a5cd3dad5fbf42cbb5ef96…`).

## 11. Pairing round 3 (order-preserving) + keyed-digest battery

`rev/pair_h3.py` implements the sound rule and writes `pair_h3.json`: **8 rows, all with `H`**.
Clean rows (candidate within a few seconds of the map's own `created_at`):
**0, 1, 4, 5, 6, 7** —

```
[0] sec=1789239391 adj9_wh2.log blob=1fcd5ee7… H=292c838cb30257f2…
[1] sec=1789239530 adj9_wh2.log blob=5b71ec7c… H=a95ac2e1497800d5…
[4] sec=1789240076 adj9_wh4.log blob=211c2cd4… H=e693b40e268c141b…
[5] sec=1789240229 adj9_wh4.log blob=505f30c7… H=8fff432a0ea293e1…
[6] sec=1789240340 adj9_wh4.log blob=61c5008a… H=624572a47977273a…
[7] sec=1789240514 adj9_wh4.log blob=5595c3c4… H=eebe704e53a5cd3d…
```

The crowded groups are still partial: `2/3` take the two earliest union candidates (their own
capture is `whcap_hits3`) and `7/8/9` find only one candidate in the ±3 s window. So the
dataset currently offers **6 fully-clean rows**.

**Batteries — all negative (recorded so they are not repeated):**

| test | rows | result |
|---|---|---|
| `#2` = HMAC-SHA256/SHA1 of (H, claims), (claims, H), (H, second) or SHA256 over the concatenations, any 4-byte window, BE and LE | 8 | **0 hits** |
| `#2`, `W0`, or any tile word appearing **inside `H`** at any 4-byte offset | 6 | **0 hits** |

⇒ `#2`/`#0` are neither keyed digests nor slices of the device's `H`; combined with slice 123
§8–§9 they are not PRNG output, not digests of claims/H, and not functions of (claims, second).
The remaining candidate sources are the builder's own arithmetic in `sub_95fc4` (slice 117's
dump) and/or per-call process state, which the *builder* consumes — hence the next step is to
reduce `sub_95fc4` against these paired rows rather than to keep probing derived quantities.