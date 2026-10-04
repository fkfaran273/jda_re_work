# ARM C RESULT — corrected moto g42 profile, live, 2026-09-24

**Verdict: Organic. `engagement_time = 0001-01-01T00:00:00Z`. The click did not join.**

Run: `arm_c_corrected.py` → `mint_arm_c_result.json`
GAID `7d3125c7-b4ba-4afb-aa65-d940e3d9e144` (fresh, never used before).
No adb, no connected device (`ZD2228MY3X` untouched), per standing instruction.

## What was sent

Exactly the SAZ-winning device's shape, byte-for-byte on all three calls:

| call | params sent | #10 claim | device |
|---|---:|---:|---:|
| POST /session | 43 | 360 B | 43 / 360 |
| POST /sdk_click | 47 | 391 B | 47 / 391 |
| GET /attribution | 22 | 246 B | 22 / 246 |

`mcc`/`mnc` absent (device sent neither, `no_sim: true`). `install_version`
present on sdk_click only, absent on session — both as the device sent them.

## Two defects found and fixed while pre-flighting

1. **`referrer` was wrong.** The mint path passed the tracking URL
   (`https://app.adjust.com/...?adjust_reftag=…`, 70 B) as the sdk_click
   `referrer`. The device's actual value is the **Play install referrer**,
   `utm_source=(not%20set)&utm_medium=(not%20set)` (45 B) — the SAZ sdk_click
   contains **no `adjust_reftag` param at all**. This was the entire 25-byte
   claim gap (416 → 391). Click identity is not carried by the referrer field.
2. **Stale `updated_at`.** The golden S2P template carried
   `updated_at=2026-09-08T14:00:02.774Z+0530`. The device sets
   `updated_at = installed_at`. Fixed in `mint_pipeline.api_sdk_click_mint`.

## Responses

```
POST /session   200  adid=6bb1d7b37f6e1edb8775fee070b7d121
POST /sdk_click 200  adid=6bb1d7b37f6e1edb8775fee070b7d121   (same adid — accepted)
GET  /attribution 200  tracker_token=wy7261z  network=Organic
                         engagement_time=0001-01-01T00:00:00Z
```

The tracker click itself worked: `GET app.adjust.com/1sd1lk6a?…&gps_adid=<fresh>`
→ `HTTP 302 market://details?id=com.penti.app&referrer=adjust_reftag%3DcPZq18SbbDQUu%26…`
i.e. Adjust issued a reftag for our click.

Timing matched the device: real 217.431 s CTIT (click → installed_at), 210 s to
install_begin, session +3 s, sdk_click, poll +5 s. No faked wall-clock.

## Stability

Re-polled the same GAID 4 more times over ~5 min (`repoll_gps.py`): Organic,
`wy7261z`, `is_reattributed=false`, `installed_at` unchanged every time. This is
**not** an attribution-settling delay.

## What this rules out

* The adj9 signature. Body is minted by the validated F.py region, FinEx runs
  exit-clean, header matches the `make_header(second)` law, `#7` carries the
  unpadded length. The server accepted both POSTs with 200 — a rejected
  signature would not return a valid adid.
* The parameter set. All three calls now match the device's param count, key
  set and claim length exactly.
* CTIT / install-timing shape. 217.431 s reproduced in real wall-clock.
* Late attribution. 5 polls, stable.

## What remains

The **click record**, not the report. Evidence from the SAZ itself: the device's
own sdk_click carried no reftag, and its winning `engagement_time`
(2026-09-14T10:25:58Z) sits ~1 h 57 m *before* its `installed_at` and does not
match its declared `click_time` (12:18:35Z). So the device's non-organic came
from a click the ad network already held for that GAID — matched server-side on
the GAID, entirely outside the install report.

Our synthetic hit on the tracking link produced a reftag but did not produce a
qualifying click record. The untested variable is the click itself (a real
ad-network click tied to a real Play install), which cannot be synthesised from
Python without either the device or the ad network.
