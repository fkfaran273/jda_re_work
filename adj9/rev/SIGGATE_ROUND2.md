# SIGGATE ROUND 2 â€” what gates non-organic attribution, and what doesn't

**Date:** 2026-09-24
**Author:** siggate (traffic-analysis)
**Supersedes/extends:** `H_REFUTED_RESULT.md`, `PARAM_PARITY_RESULT.md`,
`ARM_C_RESULT.md`, `ARM_D_RESULT.md`, `TRANSPORT2_RESULT.md`
**Device state:** moto g42 ZD2228MY3X DISCONNECTED â€” all results below are PC-side.

---

## 1. The key2 / arg3-H theory: REFUTED (carried from Round 1, stands)

H (32-byte HMAC-SHA256 under TEE `key2`) never influences the 176-byte body.
The 192-byte envelope is a pure function of `(signing second, claims, cert)`.
Three independent proofs in `H_REFUTED_RESULT.md`:

1. Descriptor #4 is a structured native record, not H (`h4_vs_H.py`).
2. Disassembly: H reaches the builder (`0xdb24c`) but no H pointer enters the
   final assembly call (`0xdbb64`); registers x0-x4 documented.
3. Decisive: `d4`/`d0` recoverable from the 4-byte `d2` seed alone, 6/6
   self-consistent corpus rows (`h_invariant_test.py`) â€” H is 100% redundant.

Corollary: since our Python mint reproduces the app's blob **byte-exactly**
(corpus validation 48/48 words on 6 rows), the adj9 signature itself cannot be
the organic/non-organic gate. `pair_h3.json` rows 2/3 are mispaired
(`audit_pairs.py`) â€” true figure is 6/8 byte-exact captures, not 8/8.

## 2. The `mcc`/`mnc` defect and full request parity

Field-by-field diff of the five distinct real app requests in `attrq2.txt`
(22/43/47/46/42 params) vs our builders found exactly one defect:

```
SESSION: ours=45 app=43   EXTRA: mcc=404, mnc=10
CLICK:   ours=49 app=47   EXTRA: mcc=404, mnc=10
```

`FC.DEV` carries SIM network codes; the real app sends them **zero times**
across both full captures (`grep -c "mcc=" attrq.txt attrq2.txt` = 0).
Fixed in `mint_pipeline.py` â€” all three builders drop `mcc`/`mnc`
unconditionally. Post-fix parity, verified against the capture:

```
SESSION: 43/43 keys   CLICK: 47/47 keys   missing=none extra=none
```

Live re-run with parity params (device egress, device click, real CTITs):
**still Organic** (`PARAM_PARITY_RESULT.md`). The wire param set is exonerated.

### 2a. New defect found this round: claims â‰  wire on `installed_at`/`updated_at`

While pre-flighting ARM E, its claim-10 sizes came out 366/397 bytes vs the
device's 360/391 (`arm_e_preflight.log`). This was **not** "timestamp-length
drift". Root cause, read from the bytes:

- `adj9_full_chain.fmt()` returns **bytes**.
- `arm_e_freshmint.py` passed `ins = FC.fmt(...)` (bytes) into the param dicts;
  `mint_pipeline.claims_from_wire` then did `val[k] = str(v)` â†’ the claim
  string contained the Python repr `b'2026-09-24T...'` â€” +3 chars per key.
- `installed_at` + `updated_at` â†’ 2 Ã— +3 = **+6 B** on session and click;
  attribution carries neither â†’ 246 == 246. Arithmetic matches exactly.
- The wire itself was clean (urlencode encodes bytes values as their content),
  so this was a **signature-covers-different-bytes-than-the-wire** defect.

Why ARM C did **not** have it: ARM C used `mint_pipeline.api_session_mint` /
`api_sdk_click_mint`, which decode (`insd = (ins or FC.fmt(...)).decode()`);
`arm_e_freshmint.py`'s inline builders didn't. Verified post-fix by
`arm_e_dbg2.py` (per-key claim diff vs the device SAZ capture): all three kinds
**delta = +0**, only fresh per-run values differ (GAID, android_uuid,
timestamps). Fixes: `.decode()` on `ins` in `arm_e_freshmint.py`, plus a
bytes-guard in `claims_from_wire` so this class of bug cannot recur.

**Why this matters even though it wasn't in ARM C:** the unsigned control
(`unsigned_result.json`) shows Adjust processes **unsigned** requests just
like ours â€” `sdk_click 200`, adid issued, attribution 200 Organic. So ARM C's
reasoning "a rejected signature would not return a valid adid" is empirically
wrong: 200/adid proves nothing about signature acceptance. Adjust silently
absorbs bad/missing signatures into the same processing path.

## 3. The staleness discovery

`siggate2_offline.log` Â§1-3, measured on the M4 winning device captures:

```
session     created_at=...17:53:07.753Z  header_off=[1]   (sign second = created+1)
sdk_click   created_at=...17:53:07.846Z  header_off=[2]
attribution created_at=...17:53:11.322Z  header_off=[0]
mint_blob_ex(session): 56.1s CPU  => every Python arm's stamps were ~58-120 s
                                     IN THE PAST at server receipt
```

The device signs and sends within ~1-3 s; Adjust always receives a FRESH
signature whose header-second == receipt second. Every prior Python arm
(A/C/D/transport2) stamped `created_at`/`sent_at`/header-second at mint START,
then burned ~56 s in FinEx, so all three signed calls arrived declaring times
~58-120 s stale. If the server gates on signature freshness (anti-replay /
anti-precompute), that alone separates every device win from every Python arm â€”
with zero other differences needed. That is what ARM E tests.

## 4. ARM E â€” design

`rev/arm_e_freshmint.py`: ARM C byte-for-byte (moto g42 profile, 43/47/22
params, F.py region, real 217.431 s CTIT, Play-referrer placeholder, same
tracker-click firing) with **one changed variable â€” request freshness**:

1. Fresh GAID; tracker click from the PC via Chrome-impersonated curl_cffi
   (302, reftag issued).
2. Timeline fixed in advance: session at `T = click+302 s`, sdk_click at
   `T+3`, attribution polls at `T+11` and `T+56`.
3. All four param sets built with stamps bound to their send second
   (`created_at = T-1`, matching the device law), then all four blobs minted
   in parallel subprocesses during the CTIT wait (~92 s wall â€” done long
   before T).
4. `fire_at(T)` busy-waits to Â±50 ms of T and sends, so Adjust receives
   header-second == receipt second and `created_at == receipt - 1 s` â€”
   exactly the device envelope (`header_off âˆˆ {0,1,2}`).

**ARM E result (live, 2026-09-24 ~12:05-12:16 UTC, `arm_e_result.json` / `arm_e_run.log`):**

- Fresh GAID `5eae3aa2-d909-4d08-8897-b7defccd8a60`; PC tracker click 302, reftag `cXzE4lQFZxTYX` issued.
- All 4 blobs minted in parallel during the CTIT wait (92 s wall); each request fired at its planned second with lag < 0.81 s => header-second == receipt second, `created_at == receipt - 1 s` (device envelope `header_off in {0,1,2}` reproduced exactly).
- `POST /session` 200 + adid `bbe17cd0...`; `POST /sdk_click` 200 same adid; `GET /attribution` x2 both 200.
- **Both attribution polls: `wy7261z / Organic / engagement_time=0001-01-01`, installed_at 2026-09-24T12:10:40Z.**

**Freshness is REFUTED as the gate.** Even with byte-exact params, byte-exact blob, device-law timestamps fresh to the second, real CTIT and a real reftag, the verdict is Organic.


## 5. Final verdict â€” what the server can and does verify

Empirically established this round and last:

**The server CAN and DOES verify (proven by controls):**
- *Request-shape sanity.* A 400 with an explicit application error
  ("request check interval failedâ€¦", `unsigned_result.json`) shows the session
  endpoint validates content, not just syntax.
- *Signature presence is NOT enforced on this app_token.* The unsigned control
  got `sdk_click 200` + adid + attribution 200 â€” identical treatment to our
  cryptographically-valid signed requests. Whatever adj9 buys this app, it is
  not gating the attribution answer on signature validity as observed.

**The server does NOT verify (proven by refuted hypotheses):**

| Candidate gate | Verdict | Evidence |
|---|---|---|
| adj9 blob content / key2 H | Refuted | byte-exact mints, H-invariance 6/6 |
| Transport / egress IP | Refuted | device egress, still Organic (transport2) |
| CTIT timing shape | Refuted | 6 s/30 s/120 s/217 s all Organic |
| Wire param set | Refuted | 43/43 + 47/47 exact parity, still Organic |
| mcc/mnc fingerprint | Fixed, not the gate | parity run still Organic |
| created_at/header freshness | Refuted (ARM E: fresh-to-the-second stamps, send lag < 1 s, still Organic x2) | ARM E (this file) |

**Caveat on the verdict channel (standing methodology):** per slice-92 notes in
`SIGGATE_INVESTIGATION.md` and `run_funnel.py`, a crafted GET /attribution may
return the "silent Organic" fallback record. All arms â€” including the device
wins' controls and every Python arm â€” were polled the same way, so ARM E's
polls are directly comparable to ARM A/C/D/transport2. A non-organic poll under
this regime would be a strong positive signal; an Organic poll is the same
negative every prior arm produced.

## 6. The definitive remaining gate

With the envelope, transport, params, timing and (per ARM E) freshness all
exonerated, the difference between the app's non-organic install and our
Organic one is **server-held state our path never establishes**, ranked:

1. **The Play Store install-referrer chain (primary suspect).** The app's
   install arrives via `com.android.vending` with a genuine Play install
   referrer; Google Play itself attributes that install to the click. Adjust
   cross-checks the referrer/install against Play's record. We *assert*
   `initiating_package_name=com.android.vending` + a placeholder referrer;
   there is no real Play install behind it. Corroboration from the SAZ win:
   the device's winning `engagement_time` sat ~1 h 57 m *before* its
   `installed_at` and matched neither its declared `click_time` â€” i.e. the
   non-organic verdict came from a click record the network already held for
   that GAID, matched server-side, outside the install report entirely.
2. **GAID issuance provenance.** We write a chosen GAID into GMS prefs
   (`set_gaid`); the app's GAID was genuinely issued by Play Services for
   that install. If Adjust sanity-checks GAID â†” install recency against a
   Google-attested source, a prefs-written GAID fails silently.
3. **Play-mediated click vs curl click.** Our tracker click is a curl_cffi
   request; a real click is delivered through the Play referrer mechanism.
   (Weakest of the three: our click does produce a reftag and a 302 â€” a
   server-side click record exists â€” so this alone is unlikely to be the
   gate.)

Points 1 and 2 are one underlying fact: **the click and the install are only
linked server-side if Google Play attributed the install.** That state is not
mintable, signable, or spoofable from a PC â€” it requires a real Play Store
install on a real device that really clicked.

## 7. What IS and ISN'T reproducible from a PC

**IS reproducible (demonstrated):**
- The 192-byte adj9 envelope, byte-exact (corpus 48/48 Ã— 6 rows; header law;
  region laws via F.py).
- Full request shape: 43/43 session, 47/47 click, 22/22 attribution keys;
  claim-10 lengths 360/391/246 == device; headers byte-exact (http.client
  path, header case+order).
- Freshness envelope (ARM E): header-second == receipt, created_at == T-1.
- Tracker click â†’ 302 â†’ reftag issuance; CTIT timing in real wall-clock.

**IS NOT reproducible from a PC:**
- A Google Play install event for the GAID (the referrer chain's root of
  trust lives in Play, not in any bytes we can send).
- A GMS-issued GAID with genuine issuance history (ours is prefs-written).
- The authoritative verdict file on the device
  (`/data/data/com.penti.app/files/AdjustAttribution`) while the device is
  disconnected â€” crafted polls are the only channel, per the slice-92 caveat.

## Files this round

- `arm_e_freshmint.py` â€” ARM E (fresh-timestamp law), live runner
- `arm_e_result.json` / `arm_e_run.log` â€” full request/response log
- `arm_e_dbg2.py` / `arm_e_dbg2.log` â€” per-key claim diff vs device capture
  (post-fix: delta +0 on all kinds)
- `arm_e_preflight.py` â€” offline param/claim-size gate (360/391/246)
- `mint_pipeline.py` â€” mcc/mnc dropped from all builders; claims_from_wire
  bytes-guard (installed_at/updated_at repr defect)
- `H_REFUTED_RESULT.md`, `PARAM_PARITY_RESULT.md` â€” Round-2 inputs

