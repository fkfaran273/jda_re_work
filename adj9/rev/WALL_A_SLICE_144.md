# SLICE 144 — the booking gate is the SIGNATURE (two isolation arms, device oracle)

Date: 2026-09-22. Scripts: `rev/verify_funnel.py`, `rev/verify_funnel2.py`.
Oracle: the app's own `AdjustAttribution` file on the moto g42 (su cat) — the
only trustworthy verdict source (slices 90/110). No crafted attribution poll
was fired in either run (the downgrade hazard, slice 97 §12).

## 0. The question left open by the funnel campaign

Every crafted funnel run (`run_funnel_result.json`, `manual_result.json`,
`funnel_redmi*.log`) ended in `200 Organic` — but read by a **crafted poll**,
which slice 92 proved answers Organic-fallback even when the record IS
non-organic. So "python-created install reads Organic" was never actually
measured; the log itself said the authoritative read was pending. These two
runs performed it.

## 1. Arm 1 — PC click + PC crafted session (`verify_funnel.py`)

Fresh GAID `ebd2868a-…`; real tracker click via curl_cffi/Chrome131
(reftag `cJz9TORUGJDwi`, VKM referrer returned); crafted-signed session
(adid `a442555a…`, `ask_in:2000`); crafted sdk_click; **no attribution polls**;
GAID written to the moto, wipe, launch, app reads its own verdict:

```
VERDICT: wy7261z / Organic   installed_at 2026-09-22T06:22:32Z  (= our session)
```

The server FOUND the record created by our crafted session (installed_at matches
exactly) and answered **Organic** to the app itself. The click preceded the
session by ~60 s. Not a poll artifact.

## 2. Arm 2 — DEVICE click + PC crafted session (`verify_funnel2.py`)

The signer-isolation arm: exactly the winning `fresh_click_install.py` shape —
fresh GAID `73a7c0b2-…` written on the device FIRST, click fired FROM the device
(curl 302), CTIT 30 s — with ONE change: the booking session is our crafted
Python signature (adid `e69766f2…`, `ask_in:2000`), not the app's. No sdk_click,
no polls. Wipe → launch → app reads:

```
VERDICT: wy7261z / Organic   installed_at 2026-09-22T06:29:50Z  (= our session)
```

## 3. Conclusion — the discriminator is the booking session's signature

| arm | click | booking session | verdict |
|---|---|---|---|
| slice 141 win (×11) | device | **app's own** | `24xg6t54 / VKM` |
| arm 1 (this slice) | PC | crafted Python | `wy7261z / Organic` |
| arm 2 (this slice) | device | crafted Python | `wy7261z / Organic` |

Between arm 2 and the 11/11 win path the ONLY remaining variable is who signed
the session. The server accepted the crafted session (200, adid issued,
installed_at booked, ask_in) but **refused to join the click's attribution** —
the booking happened, unattributed. Combined with slice 143 (the server
byte-matches rather than recomputes the blob), the picture is consistent: the
server cannot recompute the 44 entropy words (slice 142), so it gates the
*consequence* (attribution) on signature validity by whatever server-side
property/history it holds. A crafted session is a real install record with no
attribution rights.

**Pure-Python non-organic booking is therefore dead on measurement, not on
oracle blindness** — closing the last open door after slice 143. The
device-assisted path (Python drives: fresh GAID → device click → wipe →
launch → device-signed session) remains the only non-organic route: 11/11.

## 4. Also recorded

* Session `ask_in:2000` appears on crafted sessions the server processed —
  ask_in on a SESSION response is engagement/rate-limits, NOT recognition
  (contrast: `ask_in:7200000` on replayed ATTRIBUTION polls).
* The in-script verdict regex missed the file twice because the file is a
  Java-serialized `AdjustAttribution` object with the JSON embedded — grep for
  `{\"tracker_token` AFTER `tr -d '\\0'`, and poll past 120 s.
* Device GAID restored to `94ebc9a2-…` after the runs; pre-run attribution
  backup in `verify_prev_attribution.bak`.

## 5. Artifacts

* `rev/verify_funnel.py` + `verify_funnel_run1.log` + `verify_funnel_result.json`
* `rev/verify_funnel2.py` + `verify_funnel2_run1.log` + `verify_funnel2_result.json`
