---
title: WALL_A_SLICE_143
---

# SLICE 143 — FINAL: the server byte-matches the app's own blob (no verifiable property)

Date: 2026-09-21. Scripts: `rev/replay_genuine.py`, `rev/attr_exact.py`,
`rev/decisive_fresh_ip.py`.

## 0. The two measurements that settle it

**(1) A known non-organic GAID polled with OUR crafted signature → fallback.**

The OnePlus win GAID `3f2fbd51-…` is a **known non-organic** record
(`tracker 24xg6t54`, `network VKM Digital Yeni`, `creative cline_1p8t3`,
`installed_at 2026-09-21T07:45:40Z`). Polled with our lawful-region blob and the
device's **exact 22-param** attribution query:

```
[params] 22 keys (device-exact)
[attribution] 200 {"adid":"07b3af20…",
    "tracker_token":"wy7261z",        <- NOT 24xg6t54
    "network":"Organic",              <- NOT "VKM Digital Yeni"
    "installed_at":"2026-09-21T07:45:40Z"}}   <- the win's own install time
```

The server found the record (right GAID, right install time) but answered the
**generic Organic fallback** instead of the true verdict ⇒ **our signature is
rejected.**

**(2) Verbatim genuine vs 1-bit flip — the discriminating control.**

Replaying the app's own captured `/attribution` request (genuine blob + exact
query + exact headers):

```
[GENUINE verbatim] 400 {"adid":"ad003833…","ask_in":7200000}      <- RECOGNIZED
[1-BIT FLIP]       200 {"adid":"ad003833…","network":"Organic"}   <- FALLBACK
```

Same request, same GAID, **one bit of the blob changed** → recognized becomes
fallback. That is byte-level matching, not property verification.

## 1. What this closes — stated exactly

* The server does **not** check a reproducible property of the blob that we could
  compute. If it did, the 1-bit flip could not matter (a structural check would
  still pass: the flip was inside the body, the header law and section lengths
  were untouched).
* The server **recognises the exact bytes the app transmitted** for that identity,
  and answers everything else with `wy7261z / Organic`.
* Combined with: H is not a blob input (103), no MAC on the wire (125), no digest
  of the claims in the body (142), the body is 100% per-call region (142 — 44/44
  dwords differ between two signings with identical claims and second) — there is
  **nothing left to "fix" in our signature**. The missing piece is not a field,
  an order, a value or a byte; it is that the bytes were not the ones the app sent.

## 2. Consequence for the goal

| goal | feasibility |
|---|---|
| **read** a verdict in Python | **YES** — replay the exact captured bytes inside their window (slice 92 F1/F1b; this slice's GENUINE arm) |
| **mint** a recognised blob in Python | **NO** — recognition is byte-matching of the app's own transmission, not a recomputable property |
| non-organic with the device | **YES** — 11/11 (`fresh_click_install.py` / `farm_win.py`) |

## 3. Also recorded

* The device's `/attribution` query carries **exactly 22 params** (order preserved
  in `attr_exact.py`). Earlier arms sent ~47–50; that difference alone did not
  change the outcome once tested (`attr_exact.py` → still fallback), but it is now
  correctly modelled for every future run.
* A **fresh source IP** produces a genuinely new install record (adid `d9a377db…`,
  `ask_in:2000`) where the burned IP merged everything into one adid — important
  for any future device-side test.

## 4. Artifacts

* `rev/replay_genuine.py` + `replay_genuine_result.json` (GENUINE 400 vs flip 200)
* `rev/attr_exact.py` + `attr_exact_result.json` (exact 22-param call; fallback on
  a known non-organic GAID)
* `rev/decisive_fresh_ip.py` + `decisive_result.json` (fresh-IP install creation)