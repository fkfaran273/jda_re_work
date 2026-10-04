---
title: WALL_A_SLICE_118
---

# SLICE 118 — the region is on the wire: live EMIT capture of a fully-labelled mint

## 0. Outcome

The `#0/#2/#4` region is **no longer a black box**. One device call now yields the
**complete descriptor/stream plane** of a signing together with its blob — and the
signing's `second` is recoverable offline (unique inversion). We captured a mint for
which **every input is known exactly**:

| input | value |
|---|---|
| map | the 47-pair session map (`dev_p1.json`), gps_adid = original |
| H | `0102…20` (bytes 1..32, fixed by the agent) |
| sdk | 31 |
| second | **1789834707** — inverted from the blob header, **unique match in a 100 000-second window** |
| blob | `20d2b5593204a5d5656999f1…55851c2d` (192 B) |

That is the first **fully-labelled region sample** in the campaign.

## 1. What fixed the device path (both were real blockers)

| blocker | cause | fix |
|---|---|---|
| `fs17` dies seconds after start | it is a child of the launching `adb shell`; when that shell is reaped the root server is killed | `device/fs_up.py` re-launches it **parked** (Popen of a long-lived `adb shell`) and verifies the remote-device channel before use |
| `NotSupportedError` on attach | stale server state after the above | same bootstrap: single server, fresh start, verify |
| harvest returned **empty detail** | huge RPC payload dropped silently by the bridge | the agent now writes its result **to the device** (`harvest_out.json`) exactly like the proven `diffmap3` path — RPC can only lose data, never create it |
| truncated stream at 600 emits | my own cap | cap raised to 400 000; capture completed at **21 638 emits** |

`rev/agent/harvest_src.js` v2: kill-guard disarm (exit/kill/tgkill + poisoned-SIGSEGV
swallow), **lazy** EMIT hook (resolved inside `harvest()`, when `libsigner.so` is
mapped — hooking at load gave `base: null`), and the direct `nlh.a(ctx, map, H, 31)`
call (the overload-`.call()` variant silently produced nothing).

## 2. The captured plane — 11 streams (down-payment on the region)

`EMIT(q, n, v) ⇒ stream[q][base+n] = v` (semantics fixed in `vm_exec.py`).

```
q=3467672656  slots=658  n=0..657    small values (byte-like)        <- bulk payload
q=3467675824  slots=107  n=0..106    word0 == blob[0]  → the BLOB + trailing ASCII
q=3467675344  slots=84   n=0..83     ASCII as dwords: "6786","2c76",… = 336 B claims
q=3467672992  slots=36   n=0..35     len-word 0xc0 (=192); payload == blob[5..39] verbatim
q=3467672896  slots=36   n=0..35     len-word 0x90 (=144); W + 16-BYTE TILE ×7
q=3467677168  slots=8    n=0..7      sparse, RISING bit density      <- #4 shape
q=3467676784  slots=4    n=0..3      all zero                        <- #8 shape
q=3467675776  slots=1                0xdc45600c (random-looking)     <- #2 shape
q=3467677024  slots=1                len-word 0x150 (=336 == claims) <- #7
q=3467676448  slots=1                0x00000010
q=3467677408  slots=1                0x00000000
```

Two structurally decisive observations:

1. **The blob itself is walked through the EMIT plane** (`q=3467675824` starts with
   `20d2b559` = `blob[0]`), and a second buffer (`q=3467672992`, len-word 192 = the blob
   size) contains `blob[5..39]` **verbatim**. So the "merge" is literally the VM emitting
   descriptor words into output buffers — no hidden transform layer.
2. **The `#0`-shaped stream is a repeated 16-byte tile**:

```
q=3467672896: [0x90] [3204a5d5] [656999f1 020b5db1 b6fc215f] [ef8bfc98 772f01cc 3df99269]
              then [fd0b3eea 3c01f6a2 f44937a8 3543fcf7] × 7
golden #0   : [13271271] [db50f44c b63798cc dab7f51a] then [b7d0992b db50f44c b63798cc dab7f51a] × 8
```

Both are 36 words ending in a **16-byte block repeated 7–8 times**. A repeated
ciphertext block cannot come from a non-repeating keystream, so the tile is
**structural** (a fixed 16-byte slot written per iteration), not PRNG output.

## 3. Negative results, recorded so they are not repeated

| hypothesis | test | result |
|---|---|---|
| region words are `Random3(second)` output | all 12 words of our `#0` vs `next()` and vs the raw `r[]` recurrence, 4000 draws | **0 / 12** (and **0 / 8** for golden) |
| tile is a slice of the PRNG stream | 4-word run search | **no run** |
| tile/`W0` are digests of (claims, H, second) | sha256/sha1/md5/blake2s of `claims`, `H`, `claims+H`, `H+claims`, `sec_be32`, `sec_le32` | **no hit** |
| descriptor payload lands contiguously in the blob | first-16-byte search per stream payload | **no** — the payloads that do match land at **non-zero offsets** (`blob[5..]`) |

## 4. Why this changes the offline problem

Before: one device call gave **one 192-byte blob** and the region was only inferable.
Now: one call gives **(region buffers + blob + every intermediate stream)**, plus an
offline-recoverable `second`. The unknown collapses to a **regression with full labels**:

```
(claims 336 B, H, second)  ->  [q=896 36w, q=992 36w, q=7168 8w, q=6784 4w, q=5776 1w, …]
```

and the blob is a deterministic walk over exactly those buffers (slice 116 doublet:
same map + same second ⇒ **byte-identical blob**).

## 5. Next actions (priority order)

1. **Descriptor↔stream matching under FinEx.** Feed the captured streams (golden
   `len_dw` pattern 36, …, 8, 4, 1, 1, 84, …) into `fin_vm2.FinEx` and find the
   assignment that reproduces **our** blob ⇒ the stream plane *is* the descriptor plane,
   and `sub_95fc4` (dumped, slice 117) is the only remaining target.
2. **Sweep for the fit.** Same map / different second, and one-claim-changed / same
   second, collecting full planes — then fit `(second, claims, H) → region` word-by-word
   instead of guessing.
3. Reduce `sub_95fc4` (map → descriptors) using the labelled pairs as correctness oracle;
   `desc10_law` + `#7/#8/#9` are already byte-exact.

## 6. Artifacts

- `device/fs_up.py` — frida-server bootstrap + channel verify + app restart
- `rev/agent/harvest_src.js` (v2) → `rev/agent/harvest.js`; `device/harvest_run.py`
- `rev/harvest_out.json` (519 KB) — the captured plane (labelled sample)
- `rev/harvest_an.py`, `rev/harvest_an2.py` (+logs) — stream census, tile detection
- `rev/lab_sample.py` (+log) — header inversion (unique second) + derivation battery
- `rev/r3_probe.py` (+log) — Random3 disproof