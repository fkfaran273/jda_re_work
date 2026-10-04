# Wall A — slice 114: the user's own click + device data, run through our Python

Date: 2026-09-19. Script: `rev/py_dev_test.py` (`py_dev.log`, `py_dev_result.json`,
`py_dev_R_real_gaid.json`, `py_dev_F_fresh_gaid.json`).

## 0. What the user asked for

"First let's use this click gps id and its device data so we can check our Python
logics" — i.e. run our crafted chain on **their** click

```
GAID/adid : e53f99b7-dbe3-4e87-825f-9ac8a9321ae2
referrer  : adjust_reftag=caqYoINlmNv2Y&utm_source=VKM+Digital+Yeni&utm_campaign=AH
            &utm_content=vkm_0926_36&utm_term=penti_generic
device    : samsung SM-S906B (g0s), Android 16 / api 36, 1080x2340, xxhdpi,
            build BP2A.250605.031.A3, display BP2A.250605.031.A3.S906BXXUIGYI7,
            screen_layout large/long, arm64-v8a, locale en-IN
```

## 1. The mapping used (their device data → the desc10 claim law)

| our claim key | value taken from their dump |
|---|---|
| `device_name` | `SM-S906B` (model) |
| `device_manufacturer` | `samsung` |
| `os_name` / `os_version` | `android` / `16` |
| `api_level` | `36` (sdk) |
| `os_build` | `BP2A.250605.031.A3` (build) |
| `hardware_name` | `BP2A.250605.031.A3.S906BXXUIGYI7` (display) |
| `display_width` / `display_height` | `1080` / `2340` (resolution) |
| `screen_size` / `screen_format` / `screen_density` | `large` / `long` / `xxhdpi` (display_metrics) |
| `cpu_type` | `arm64-v8a` |
| `language` | `en` |
| `connectivity_type` | `1` (WiFi) |
| `gps_adid` | `e53f99b7-…` (their adid) |

Everything else comes from the device's own golden map (app_token, app_version,
package_name, `adj_signing_id`, `client_sdk`, `headers_id`, `native_version`, the
environment/retry/wait fields), so the claim set is exactly the session law.

## 2. Results (`py_dev.log`, verbatim)

```
=== R_real_gaid  gps=e53f99b7-dbe3-4e87-825f-9ac8a9321ae2
[R/pre]       http=200 network=Organic eng=0001-01-01 inst=2026-09-19T07:45:10.657240
              <- nanosecond precision = NO record existed for this GAID yet
[R/session]   exit-clean http=200 adid=b46e1e86b6900592dbcf702f3473e10e ask_in=2000
[R/sdk_click] exit-clean http=200 adid=b46e1e86… (same)
[R/read0..2]  http=200 network=Organic creative=None eng=0001-01-01T00:00:00
              inst=2026-09-19T07:46:03Z      <- second precision, and = OUR session's time

=== F_fresh_gaid  gps=e200501e-e2c0-4b8a-b8b2-3a48e25838d1
[F/pre]       ns-only placeholder (no record)
[F/click]     302 reftag=adjust_reftag=cf1opa6JgynWz
[F/session]   exit-clean http=200 adid=d5e452843549143ef386d9549858a177 ask_in=2000
[F/sdk_click] exit-clean http=200 same adid
[F/read0]     http=200 network=Organic eng=0001-01-01 inst=2026-09-19T07:50:56Z
```

## 3. What this establishes

* **The identity is not the variable.** Their real GAID with their real device
  data (ARM R) and a fresh GAID with the same data (ARM F) give the **identical**
  answer: package accepted, record created by our session (`installed_at` = our
  time, confirmed by the second-precision read vs the ns placeholder before),
  **no engagement joined, `network: Organic`**.
* This is a *stronger* form of slice 113's arm S: there the click was fired by us
  moments earlier; here the click **pre-existed** (their `caqYoINlmNv2Y` reftag)
  and the GAID had **no prior install record**, so a pending click was available
  and our first session still did not consume it.
* ⇒ "If the device can do it, we can do it" fails precisely because what the
  device does is not a property of the identity, the device data, the click or the
  claim values — it is a property of the **bytes its process minted** (slices
  111/112: same identity+claims+second+auth header, device bytes `400 RECOGNIZED`
  vs ours `200 NOT`; only the byte-identical body passes; the per-call region is
  not payload-derived).

## 4. Consequence for that GAID (stated plainly)

Our crafted session stamped an install record on `e53f99b7-…` at
`2026-09-19T07:46:03Z` reading **Organic**. Adjust's own rule then applies: a
genuine test wants a **fresh GAID whose click precedes its first session**, so for
a device-side non-organic win, fire a new click with a new GAID rather than
re-using this one. (Documented because the pre-read was taken precisely so this
was visible, and because it was the user's explicit instruction to use this GAID.)

## 5. Artifacts

| file | role |
|---|---|
| `py_dev_test.py` / `py_dev.log` / `py_dev_result.json` | the two-arm run (their GAID + control) |
| `py_dev_R_real_gaid.json`, `py_dev_F_fresh_gaid.json` | per-arm records (pre-read, click, session, sdk_click, all polls) |
| `py_book_test.py` / `py_book.log` | slice 113 (S/K/C arms) reused by this script |