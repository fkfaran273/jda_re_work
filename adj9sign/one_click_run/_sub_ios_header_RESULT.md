# _sub_ios_header — the iOS adj9 header law, packaged + hardened

Authorized security research on our own captured traffic. Companion to
`_sub_ios_header.py` (the implementation + full verification battery) and
`_sub_ios_header_vectors.json` (the 28 regression vectors).
**Everything below is machine-verified: `python _sub_ios_header.py` → ALL CHECKS PASSED (exit 0).**
No existing file was modified; the SAZ and `_sub_ios_timing.json` are read-only inputs.

---

## 1. The law (final, verified 28/28)

```
seed = time(NULL)                                   # unix seconds
x    = seed mod (2^31 - 1);  if x == 0: x = 1       # MINSTD state must be nonzero
D[k] = (16807 * D[k-1]) mod (2^31 - 1)  k = 1..8    # D[0] = x   (MINSTD / Park–Miller)
w_i  = D[2i+1] ^ D[2i+2]                i = 0..3    # words pair the POST-STEP draws
header = BE32(w0) || BE32(w1) || BE32(w2) || BE32(w3)   # 16 bytes = signature[0:16]
```

**Hardening note on indexing (the one trap in this law).** The words pair the
eight values *after* stepping the state (draws 1..8), not the seed state itself.
Read literally as `w_i = d[2i] ^ d[2i+1]` with `d[0] = x` inside the words, the
law reproduces **0/28**; pairing draws 1..8 reproduces **28/28**. Equivalently:
let `draws[0..7]` be the eight post-step values; then `w_i = draws[2i] ^ draws[2i+1]`.
This matches the independent finds in `_ios_solved.py` / `_ios_invert.py`.
With `x` in the words, all other variants (Android bionic TYPE_3, lrand48,
hybrid LCGs from the earlier `_ios_*.py` probes) stay at 0/28 — see §6.

**Worked example (sid 142):** second `1787553332` (2026-08-24T12:05:32+05:30),
`x = 1787553332`, draws D1..D8 =
`112629394, 1029131951, 787407519, 1163939019, 894551810, 199258023, 1002586888, 1321132254`
→ words `0x3be1d83d, 0x6b8eae54, 0x3eb1a8a5, 0x757ca3d6` → header
`3be1d83d6b8eae543eb1a8a5757ca3d6` = the captured signature prefix.

## 2. Reproduction + uniqueness (task 1)

- 30 signed requests in the capture, **28 distinct** 16-byte headers
  (one header shared by sids 142/143/144 — the session-establishment burst —
  all others appear once).
- For every distinct header, the scan of `[ClientBeginRequest-600, +600]`
  reproduces it **28/28**.
- **Uniqueness, both directions:** each header is matched by **exactly one**
  second in its window (no header matched by 2+ seconds); all 28 signing
  seconds are distinct (no second matches 2+ headers); for the shared header,
  the *same* unique second is the single hit in each of the three sharers'
  windows.
- **Wide injectivity scan:** all 176,987 consecutive seconds spanning
  [min(signing)−1d .. max(signing)+1d] = [1787466932 .. 1787643918] produce
  **176,987 distinct** headers — zero collisions in a ±1-day neighborhood, and
  each of the 28 capture headers occurs exactly once in the span. The law is
  invertible at capture-time scale: header → the one signing second.
- Cross-check vs `_sub_ios_timing.json`: all 30 requests agree on the decoded
  signature header, `adj_verification_b64` and `ClientBeginRequest` unix time.
  *Data-hygiene note:* that file's `header16_hex` field actually holds the
  decoded **adj_verification** (27 bytes), not the 16-byte signature header.

## 3. Regression vectors (task 2) — `_sub_ios_header_vectors.json`

28 rows `{sid, header16_hex, signing_second, offset_vs_request_second}`
(offset = signing_second − floor(ClientBeginRequest unix)). Distribution:

| offset | count |
|-------:|------:|
| −9 | 1 (sid 142, the first sdk_click — signed ~9 s before the proxy saw it) |
| −2 | 1 (sid 2903) |
| −1 | 2 (sids 1949, 2959) |
| 0  | 21 |
| +1 | 3 (sids 2795, 2831, 2864) |

Matches the expected profile (mostly 0, a few ±1, one −9; plus one −2).
Endpoints: first vector sid 142 @ 1787553332, last sid 3429 @ 1787557518 —
the capture's signing seconds span ~7 minutes.

## 4. adj_verification generator (task 3)

```
adj_verification = BASE64( KEY_cycle XOR b'{"os_name":"<os>"}' )
KEY_cycle = b"Quoh8uafohgh7CahM2h"      # 19 bytes, cycled to plaintext length
```

- `{"os_name":"android"}` → `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` — **asserted OK**
- `{"os_name":"ios-simulator"}` → `KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb` — **asserted OK**
- `{"os_name":"ios"}` (what a REAL device would send) → **`KlcAG2cbAAsKSl1KXiwSSjA=`**

**Key-length finding (hardening):** the 21-char literal
`"Quoh8uafohgh7CahM2hQu"` quoted elsewhere is the 19-byte key plus the first
two bytes of its own repeat. A 21-byte cycle reproduces the android vector but
breaks the 27-byte ios-simulator vector at byte 21 (needs `'o'`, gives `'Q'`);
the 19-byte cycle reproduces every vector and is the correct pad. The capture
confirms it from the device side: all 30 captured adj_verification values
decode to `{"os_name":"ios-simulator"}` (the modded device spoofs simulator).

## 5. MINSTD edge behavior (task 4)

- The MINSTD state may not be 0 (0 is absorbing under ×16807 mod 2³¹−1), so
  `seed ≡ 0 (mod 2^31−1)` falls back to `x = 1`.
- The fallback stream **is** the seed-1 stream: seconds `0`, `1`, `2^31−1`
  (2038-01-19T03:14:07Z) and `2^31−1+1` (03:14:08Z) all mint the *same* header
  `10d67b565a02a0f358376d4a50e08726` (verified).
- Therefore the **only** adjacent-second collisions on the whole timeline are
  the pairs {0, 1}, {2³¹−1, 2³¹−1+1}, {2·(2³¹−1), …} — 1970 epoch zero and the
  2038 / 2106 wraps. For every seed in `[2, 2^31−2]` — i.e. every real
  deployment second before 2038-01-19T03:14:07Z — the fallback never activates
  and neighboring seconds always mint distinct headers; the ±1-day scan (§2)
  confirms zero collisions empirically around the capture. Practical verdict:
  **the x=1 fallback cannot collide with a neighboring second's stream in
  practice**; the theoretical 2038-boundary pair is 12 years away from the
  capture (Aug 2026) and merely makes two adjacent seconds share a header once.

## 6. Cross-check against the Android law (task 5)

`import adj9_signer` (same folder) — `make_header` (bionic `Random3` TYPE_3:
31-word additive-feedback LCG, 310-draw warm-up, Schrage multiply, pair-XOR):

- Over the union of all iOS ±600 windows, [1787552732 .. 1787558118]
  (5,387 seconds), the Android law reproduces **none** of the 28 iOS headers;
  at each of the 28 iOS signing seconds the two laws always disagree.
- The Android law **does** reproduce all 9 of its own embedded gold vectors at
  the header level (`make_header(g['second']) == blob_hex[:32]` for all 9), and
  the file's own `self_test()` + `self_test_blob()` (full 192-byte mints) also
  pass — e.g. gold vector 1: second 1790694158 → header
  `26148db92c7134c438f3b3d7219b3684` = captured blob prefix.

Both laws are genuinely distinct MINSTD derivatives living side by side:
Android = warm LCG stream from a raw seed; iOS = 8 straight Park–Miller draws
from `time(NULL) mod 2³¹−1`. No cross-contamination, no shared outputs.

## Verdict

The iOS header law is packaged (`make_ios_header` / `minstd_draws` /
`invert_ios_header` in `_sub_ios_header.py`), verified 28/28 with strict
uniqueness, and hardened with two corrections that any future implementation
must respect: (1) words pair the **eight post-step draws**, never the seed
state; (2) the adj_verification pad is the **19-byte** key cycle. Regression
vectors are frozen in `_sub_ios_header_vectors.json`.
