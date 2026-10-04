# LADDER 2 — does the NOW-FAITHFUL (F.py) region get RECOGNIZED?

Date: 2026-09-24. Script: `rev/py_ladder2.py`. Results: `rev/py_ladder2_result.json`.
Rebuilt `py_ladder.py`'s recognition ladder EXACTLY (same genuine captured query,
same already-consumed identity, same signing second, same 21-claim #10 shape,
same transport/headers) and changed **only the blob source**: `mint_blob()` with
the F.py faithful region instead of the previously-unfaithful region.

## Test identity (safe, already burned — identical to py_ladder)

- gps_adid `0e789180-17da-440b-b1c3-0349d40e0e93` (adid `06a7174d…` already
  booked/consumed) — no live GAID touched, no fresh-GAID attribution polls.
- signing second `1789474915` (genuine header law holds: `make_header(sec)`).
- query = 22 params; #10 claims = 21 keys, padded 248 / unpadded 246 (parity
  with the original py_ladder mint).

## Arms and results

| arm | blob | region laws (L1/L2/L3) | HTTP | verdict |
|---|---|---|---|---|
| A0 | genuine verbatim (control) | — | **400** | **RECOGNIZED** — `ask_in:7200000` |
| A1p | `mint_blob`, F region, V=`0xa1a1f00d` (fresh), pid=12345 | **True/True/True** | 200 | **NOT recognized** → Organic `wy7261z` |
| A1pp | `mint_blob`, F region, V=`make_V(sec,800000)`=`0x6aa50d63` | **True/True/True** | 200 | **NOT recognized** → Organic `wy7261z` |
| A2 | 1-bit flip of A1p (control) | — | 200 | not recognized |
| A6 | A1p with L1 (`U2^U0`) deliberately broken | **False/False/False** | 200 | not recognized |

Response bodies: A0 = `{"adid":"06a7174d…","ask_in":7200000}`; A1p / A1pp /
A2 / A6 = identical `200` Organic body
`{"adid":"06a7174d…","attribution":{"tracker_token":"wy7261z","tracker_name":"Organic",…}}`.

Mint diagnostics (all arms): `status=exit-clean`, `nrand=8`, 192 B, header law
OK, 44/48 body dwords differ from the genuine blob.

## Verdict on the question

**A1p / A1pp = NOT RECOGNIZED (200 Organic).** The NOW-FAITHFUL F.py region does
**not** unlock recognition. The gate is **not** passed offline.

## What this proves about the server's check

- **It is NOT the region structural laws.** A1p/A1pp satisfy L1/L2/L3 (a
  law-passing faithful region); A6 deliberately breaks L1/L2/L3. A1p, A1pp and
  A6 all return the **identical 200 Organic** response. If the server gated on
  the laws, a law-passing region (A1p) would have separated from a law-broken
  one (A6). It did not ⇒ **the server does not test the region laws.**
- **⇒ The prior "Organic because the region was unfaithful" explanation is
  REFUTED.** F.py produces a law-satisfying, structurally faithful region for any
  seed, and a blob carrying it is still Organic — identical to the earlier
  unfaithful-region mint. Region faithfulness is not the blocker.
- **What the server actually distinguishes:** genuine-exact-bytes (A0 → 400)
  vs everything else (A1p/A1pp/A2/A6 → 200). On a **replay of an already-
  consumed query**, the only body the server recognizes is the stored genuine
  artifact; a freshly-minted region is never the expected bytes.

## Critical scope caveat (why this ladder cannot test a fresh install)

This ladder deliberately replays one **burned/consumed** query (the safe
identity). Recognition on such a replay requires reproducing the genuine body
(the device's actual region for that specific signing). F.py reproduces a region
for **any** seed — but *not* the specific (V, pid) the genuine device happened
to use for *this* already-consumed signing, and the fill-instant µs is not on
the wire, so the server cannot recompute our fresh region either. Therefore this
ladder is **incapable of showing "faithful region ⇒ recognized" on a replay**,
and its 200 on A1p does not by itself predict fresh-install booking behavior.

The real question — "does a faithful F.py region book NON-ORGANIC on a **fresh**
clicked GAID?" — is only answerable on the funnel, off the stored-artifact
replay confound.

## Conclusion + recommended next step

- The recognition gate is **not law-based**; A6 proves it. The faithful region
  does not change the Organic outcome on a replay.
- Offline recognition on a stored/burned query stays closed; the only
  recognized body there is the genuine artifact.
- **Next step: the slice-144 funnel arms (`mint_testbed.md`) with a FRESH
  clicked GAID and the device as the verdict oracle** (`mint_pipeline.py
  arm-a` / `arm-b`, gated behind `--live`). A fresh install has no stored
  artifact, so it is the only context where a faithful region could separate
  recognized from Organic. Run mint-signed `/session` (+ `sdk_click` for arm-a)
  with `F.py` region, **no crafted attribution polls**, and read the verdict
  from the moto g42's own `AdjustAttribution` (`wy7261z/Organic` = fail,
  anything else = non-organic).

## Artifacts

- `rev/py_ladder2.py` — the harness (reuses py_ladder transport + identity).
- `rev/py_ladder2_result.json` — per-arm HTTP + full bodies + mint diagnostics.
