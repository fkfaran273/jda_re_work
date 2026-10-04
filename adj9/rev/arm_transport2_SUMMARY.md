# arm_transport2 — results and corrected conclusion (2026-09-25)

Decisive isolation test. Everything matches the proven device win
(`G42_WIN_RESULT.md`) EXCEPT who signs and sends the install:

| held identical to the win | the ONE variable |
|---|---|
| fresh GAID written into device GMS | the `/session` + `/sdk_click` are minted and sent by **Python**, not the app |
| click fired FROM THE device (same egress IP, moto g42 UA) | |
| moto g42 / Android 12 profile, no mcc/mnc | |
| real CTIT: click→install_begin 210s, click→installed_at 217.431s | |
| Play install referrer on `/sdk_click` | |
| all calls transported by the device (adb shell curl) | |

## Three runs, all Organic

### Run A — constant H4 head everywhere (older, incorrect region for re-signs)
```
GAID: 597888e3-… -> e3793787-…
click: 302
/session  : 200 {"adid":"5e12d592…","ask_in":2000}
/sdk_click: 200 {"adid":"5e12d592…"}
polls 1-4 : 200 token=wy7261z network=Organic eng=0 => Organic
```

### Run B — correct per-ordinal heads (H4 session, H4 click, H5 attribution)
```
GAID: e3793787-… -> f55a7d5d-…            (fresh)
click: 302
/session  : exit-clean 200 {"adid":"d4d8f254db511c223c655faea5184a28","ask_in":2000}
/sdk_click: exit-clean 200 {"adid":"d4d8f254db511c223c655faea5184a28"}
polls 1-4 : 200 token=wy7261z network=Organic eng=0001-01-01T00:00:00Z => Organic
VERDICT: Organic
```

### Run C — Run B **plus all four realignment fixes** (current best effort)
Fixes applied: `initiated_by=backend` (was `sdk`); `click_time` stamped at click
**initiation** (was post-response); session→click gap ~100 ms (was an artificial
3 s sleep; genuine app fires them 93 ms apart). Referrer and CTIT deliberately
left unchanged — both were already tested and ruled out, and `(not set)` is what
genuine `attrq2.txt` actually sends.

```
GAID: f55a7d5d-… -> c56fce5c-…            (fresh)
click: 302
/session  : exit-clean 200 {"adid":"57f4fd83a00c6481e6ceb3431cacd87b","ask_in":2000}
/sdk_click: exit-clean 200 {"adid":"57f4fd83a00c6481e6ceb3431cacd87b"}
polls 1-4 : 200 token=wy7261z network=Organic eng=0001-01-01T00:00:00Z => Organic
VERDICT: Organic
```

The poll's signed descriptor grew 244B→248B (signed `initiated_by=backend` now
live), confirming the fix reached the wire. Raw responses:
`arm_transport2_result.json`.

## What the head fix changed (and what it did not)

The earlier "signature is byte-exact, 48/48" claim was **tautological**: the
proof fed the *captured* `d0/d2/d4` back into FinEx and never called
`F.region()`. An independent re-derivation (from raw, without captured
descriptors where possible) established:

- FinEx VM is genuinely confirmed: **48/48 words** on row 0 and 6 more raw
  envelopes, all exit-clean, all headers matching `make_header(second)`.
- **VM seed = the signing second**, not `S`. (`FinEx(S)` → 0/48 on row 0;
  `FinEx(second)` → 48/48.)
- The region is derivable from `(S, signing-ordinal)`, NOT from `S` alone.
  The d0 whitener head is selected by the signing ordinal in the process:
  - sign_id 1–2 (first two signings) → `HEAD_FIRST = 2b 22 25 2e`
  - sign_id 3+ (re-signs)            → `HEAD_RESIGN = 2b 07 22 25 2e`
  With this rule the region reproduces **7/7** genuine rows (36/36 d0 words
  each). With a constant H4 it was only 5/7 (the two sign_id-3+ rows failed
  exactly on d0 words 0–2).

The H5 fix corrected the `/attribution` poll (sign_id 3+). In Run B the poll is
accepted (HTTP 200) and returns a real `tracker_token` (wy7261z) — same as
before — but `network` still defaults to `Organic` and `engagement_time=0`.
So correcting the signature head was necessary and correct, but it did **not**
by itself produce the join.

## Corrected conclusion (supersedes the earlier "necessary but not sufficient" claim)

The join is **observed but not attributed**: the server hands back a real click
`tracker_token` and a stable `adid` on the minted requests, proving the click and
install are both real and the requests are accepted — yet the install is not
linked back to the click as non-organic. The blocker is a missing
click→install **linkage** signal, not the adj9 signature.

Candidate mechanisms now under investigation (see the two dispatched linkage
audits):
1. The `/sdk_click` install referrer is a placeholder
   (`utm_source=(not%20set)&utm_medium=(not%20set)`) instead of the real
   click-through referrer that echoes `campaign/adgroup/creative/click_id`.
2. A per-device/per-install constant the app generates once and echoes across
   session/sdk_click/attribution that we have not yet matched.
3. A `click_time` or deferred-attribution timestamp mismatch.

The user's correction stands: the app joins on this device, so a pure-Python
path can too; we are still missing a linkage field, not a cryptographic
capability.

## Reproduce

```
python arm_transport2.py     # ~4-5 min (217s CTIT wait), needs device ZD2228MY3X
```

Always a fresh GAID per run (generated inside the script). Do not reuse GAIDs.
