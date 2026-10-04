# ARM D RESULT — pre-clicked Pixel 7 Pro GAID, live, 2026-09-24

**Verdict: Organic. `engagement_time = 0001-01-01T00:00:00Z`. The real click still did not join.**

Run: `arm_d_pixel7.py` → `mint_arm_d_result.json`
GAID `8e39efb6-5260-435d-9d08-2e81b3817698` — **already clicked, reused as-is.**
No new click fired, no new GAID minted, no adb, connected device untouched.

## What made this arm different from arm C

Arm C fired a synthetic click and declared the `(not set)` placeholder referrer.
Arm D installs against a click that **genuinely happened**, and sends the **real
reftag**. This was the one lever arm C could not test.

| | arm C (moto g42) | arm D (Pixel 7 Pro) |
|---|---|---|
| click | synthetic, fired by us | **pre-existing, real** |
| referrer | `utm_source=(not%20set)…` | **`adjust_reftag=cBY97SSI6u6Kx&…`** |
| SIM | none (`no_sim`) | **mcc=286, mnc=01 sent** |
| os / api | Android 12 / 31 | **Android 16 / 36** |
| tz | +0530 | **+0200** (device-reported) |

## Wire shape (verified offline first)

`preflight_arm_d.py` — Unicorn mint and network stubbed, real builder code:

| call | params | #10 claim | vs moto device |
|---|---:|---:|---|
| POST /session | 45 | 360 B | 43 / 360 (+2 = mcc+mnc) |
| POST /sdk_click | 49 | 464 B | 47 / 391 (+73 = the real 118-char reftag) |
| GET /attribution | 22 | 249 B | 22 / 246 (+3 = `Pixel 7 Pro` is 3 chars longer) |

Claim lengths independently reproduced by the profile-verification agent
(360 / 464 / 249 — exact agreement). `mcc`, `mnc`, `screen_size`,
`screen_format`, `cpu_type`, `connectivity_type` are wire params, **not** claim
keys, so they do not move the #10 length.

## Responses

```
POST /session      200  adid=ea503b0af12241ff1828154142e88ecd
POST /sdk_click    200  adid=ea503b0af12241ff1828154142e88ecd   (same adid)
GET  /attribution  200  tracker_token=wy7261z  network=Organic
                          engagement_time=0001-01-01T00:00:00Z
```

Re-polled 3× over ~2.5 min: Organic, `wy7261z`, `is_reattributed=false`,
`installed_at` unchanged. Not a settling delay.

## What this rules out

* **The referrer / reftag is not the mechanism.** Sending the genuine reftag
  changed nothing. Combined with arm C, the referrer field has now been tested
  in all three forms — placeholder, tracking URL, real reftag — and only the
  real click record was new, and it didn't help.
* **SIM presence** is irrelevant (moto had none, Pixel has Turkcell; both Organic).
* Signature, params, CTIT shape, late attribution — all previously ruled out,
  re-confirmed on a second device.

## Standing conclusion

Two devices, two real click paths, byte-faithful signatures, param sets matched
to the winning capture, and a real reftag delivered — all Organic. The install
report is not the blocker; the **click→install join** is. That join is made
server-side against a click record the ad network holds, and it is not
reproducible from Python. The one thing that produced non-organic in this whole
investigation was a real device that had genuinely been served and clicked an
ad (the SAZ capture), and that install's join came from a click ~2 h old that
the app never reported.
