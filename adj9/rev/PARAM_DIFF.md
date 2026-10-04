# Param-level diff — REAL DEVICE (SAZ) vs Python mint path

Ground truth: `penti_android_test.saz` sessions 1/2/3 (POST /session, POST /sdk_click, GET /attribution). Device: moto g42, Android 12, api 31, motorola, tr, S2SE32.28-28-4, high, 1080x2237, no mcc/mnc.

Python path: `mint_pipeline` builders over the Redmi/Android-15 `run_funnel.DEVICE_JSON` profile. Built offline, no send.

## 1. Param counts

| kind | device | python |
|---|---:|---:|
| session | 43 | 45 |
| sdk_click | 47 | 49 |
| attribution | 22 | 22 |

## 2. Claim-string (#10) lengths

| kind | device (SAZ) | python (Redmi) | corrected (moto g42) |
|---|---:|---:|---:|
| session | 360 | 355 | 360 |
| sdk_click | 391 | 386 | 391 |
| attribution | 246 | 248 | 246 |

## 3. Three-way param diff (per kind)

### session

- device-only params: 0
- python-only params: 2
  - `mcc` = `405`
  - `mnc` = `908`
- same-name-different-value: 12
  - `api_level`: device=`31` python=`35`
  - `created_at`: device=`2026-09-14T17:53:07.753Z+0530` python=`2026-09-14T17:53:07.928Z+0530`
  - `device_manufacturer`: device=`motorola` python=`Redmi`
  - `device_name`: device=`moto g42` python=`2406ERN9CI`
  - `display_height`: device=`2237` python=`1080`
  - `display_width`: device=`1080` python=`2312`
  - `hardware_name`: device=`S2SE32.28-28-4` python=`breeze`
  - `language`: device=`tr` python=`en`
  - `os_build`: device=`S2SE32.28-28-4` python=`AQ3A.240912.001`
  - `os_version`: device=`12` python=`15`
  - `screen_density`: device=`high` python=`xxhigh`
  - `sent_at`: device=`2026-09-14T17:53:07.808Z+0530` python=`2026-09-14T17:53:07.942Z+0530`

### sdk_click

- device-only params: 0
- python-only params: 2
  - `mcc` = `405`
  - `mnc` = `908`
- same-name-different-value: 13
  - `api_level`: device=`31` python=`35`
  - `created_at`: device=`2026-09-14T17:53:07.846Z+0530` python=`2026-09-14T17:53:07.961Z+0530`
  - `device_manufacturer`: device=`motorola` python=`Redmi`
  - `device_name`: device=`moto g42` python=`2406ERN9CI`
  - `display_height`: device=`2237` python=`1080`
  - `display_width`: device=`1080` python=`2312`
  - `hardware_name`: device=`S2SE32.28-28-4` python=`breeze`
  - `language`: device=`tr` python=`en`
  - `os_build`: device=`S2SE32.28-28-4` python=`AQ3A.240912.001`
  - `os_version`: device=`12` python=`15`
  - `screen_density`: device=`high` python=`xxhigh`
  - `sent_at`: device=`2026-09-14T17:53:07.871Z+0530` python=`2026-09-14T17:53:07.970Z+0530`
  - `updated_at`: device=`2026-09-14T17:52:12.431Z+0530` python=`2026-09-08T14:00:02.774Z+0530`

### attribution

- device-only params: 0
- python-only params: 0
- same-name-different-value: 5
  - `api_level`: device=`31` python=`35`
  - `created_at`: device=`2026-09-14T17:53:11.322Z+0530` python=`2026-09-14T17:53:11.666Z+0530`
  - `device_name`: device=`moto g42` python=`2406ERN9CI`
  - `os_version`: device=`12` python=`15`
  - `sent_at`: device=`2026-09-14T17:53:11.358Z+0530` python=`2026-09-14T17:53:11.696Z+0530`

## 4. Cause of the session claim-length gap

The desc10 law signs only the law keys; profile fields that ARE law keys (device_name, hardware_name, os_build, api_level, os_version) change the concatenated claim length directly.

Per-key session claim value lengths (python_redmi - device):

| key | device | python | delta |
|---|---:|---:|---:|
| `device_name` | 8 | 10 | +2 |
| `hardware_name` | 14 | 6 | -8 |
| `os_build` | 14 | 15 | +1 |

Total session claim: device=360, python=355, gap=-5.

## 5. Corrected profile reproduces

Using the device's own param set, `build_desc10` gives: session=360, click=391, attribution=246.

## 6. CTIT

- click_time -> installed_at = 217.431 s (3.62 min)
- click_time -> install_begin_time = 210.000 s
