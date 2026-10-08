# FINAL CHECK -- adj7 builders vs the golden booked capture

Golden: `payrupik_new_.saz` (moto g42, genuine in.hanafintech install, BOOKED non-organic: tracker 248wk8ym VL-Alliance::HM2::HM2_1722_), raws `cap/payrupik_new/raw/4N_c.txt`. Cross-check: `payrupi.chls` spans (Pixel 6a family, Content-Length-verified).  Rebuild identity: `last_run.json`.  Run: 2026-10-06 22:11:32.

- **Headers**: request/header tables (names, order, values) MATCH on all three funnel endpoints (the golden's absolute-form request URI is a Fiddler CONNECT artifact).
- **H-law**: our CURRENT claims law reproduces the golden's commitment H on /session, /sdk_click and /attribution -- in fact the ENTIRE 304-B blobs rebuild byte-exact (tag ok, record c == campaign cert prefix).  The signer is clean.
- **Bodies**: field SETS match; the ENCODING scheme (urlencode/quote_plus for POST, quote for GET) reproduces every golden byte (+, %20, %3A, %2B all correct).  BUT 5 structural root causes remain in ORDER/VALUES:
  - /session: ORDER -- golden places [partner_params] at golden pos 6 (right after `hardware_name`) -- ours does not; ours injects [partner_params, initiating_package_name] (our pos 31) where the golden has nothing -- not in the golden; golden places [initiating_package_name] at golden pos 41 (right after `package_name`) -- ours does not
  - run_install.py build_session_request: display_height value `2400` but the golden device sends `2237`
  - /sdk_click: ORDER -- golden places [partner_params] at golden pos 5 (right after `app_version`) -- ours does not; ours injects [partner_params, click_time_server] (our pos 17) where the golden has nothing -- not in the golden; golden places [click_time_server] at golden pos 37 (right after `screen_format`) -- ours does not; golden places [install_begin_time_server] at golden pos 40 (right after `google_play_instant`) -- ours does not; ours injects [install_begin_time_server] (our pos 45) where the golden has nothing -- not in the golden
  - run_install.py build_click_request: display_height value `2400` but the golden device sends `2237`
  - /attribution: ORDER -- ours injects [push_token] (our pos 22) where the golden has nothing -- not in the golden

- **VERDICT: NO-GO** -- apply the fixes in section 5, re-run `python final_check.py`, expect zero structural diffs, then GO.

---

## 1. Golden raw requests (cap/payrupik_new/raw/, saz primary)

| raw | request | body B | Content-Length | truncation | JSON body agrees |
|---|---|---|---|---|---|
| 42_c.txt | POST https://app.adjust.com/session | 1124 | 1124 | OK | see below |
| 43_c.txt | POST https://app.adjust.com/sdk_click | 1420 | 1420 | OK | see below |
| 44_c.txt | GET https://app.adjust.com/attribution?initiated_by=backend&gps_adid_attempt=1&api_level=31&app_version=3.0.4&app_token=smxi7gqwu39c&os_version=12&created_at=2026-10-06T15%3A47%3A41.741Z%2B0530&device_type=phone&gps_adid=0a5863d0-66f6-4d15-b9ab-d388b77c8ba3&foreground=1&android_uuid=bd338228-9793-4b65-a4c6-2cc461e2801f&sent_at=2026-10-06T15%3A47%3A41.754Z%2B0530&offline_mode_enabled=0&device_name=moto%20g42&environment=production&needs_response_details=1&attribution_deeplink=1&package_name=in.hanafintech&os_name=android&ui_mode=1&gps_adid_src=service&tracking_enabled=1 | 0 | - | OK | see below |
| 45_c.txt | POST https://app.adjust.com/event | 1114 | 1114 | OK | see below |

Extracted-JSON cross-check (raw pairs == JSON body dict):
- POST /session: MATCH
- POST /sdk_click: MATCH
- POST /event: MATCH

## 2. chls cross-check (payrupi.chls, Pixel 6a family -- non-truncating)

chls field counts (Content-Length-verified spans): /attribution=23, /event=49, /sdk_click=50, /session=46

Golden relative signing seconds (from the capture's own stamps):
- click_time          = click + 0
- /session  created_at = click + 433 s
- /sdk_click created_at = click + 433 s
- /attribution created_at = click + 436 s

Rebuild identity = last_run.json: gaid `264fd707-78ca-4f46-8c87-e63d106de56f`, android_uuid `5bab7408-a750-42ba-a624-7297390eb3d3`, click_second 1791303314.

---

## Endpoint POST /session

**Request line**
- golden : `POST https://app.adjust.com/session HTTP/1.1`
- ours   : `POST /session HTTP/1.1`
- absolute-form URI in the golden = capture-through-CONNECT-proxy artifact (Fiddler); a direct Dalvik call sends origin-form. Expected difference, not a device behaviour diff.

**Headers (names, order, values)**

| # | golden | ours (call()) | verdict |
|---|---|---|---|
| 1 | `Client-SDK: android5.6.0` | `Client-SDK: android5.6.0` | MATCH |
| 2 | `Authorization: Signature signature="55DBE22A2D099DAF5368D1091190EE1` | `Authorization: <per-install signature -- format check>` | MATCH (blob 304 B, sid 1300000, alg adj7, hdr 8, nv 3.62.0) |
| 3 | `Content-Type: application/x-www-form-urlencoded` | `Content-Type: application/x-www-form-urlencoded` | MATCH |
| 4 | `User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S` | `User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S` | MATCH |
| 5 | `Host: app.adjust.com` | `Host: app.adjust.com` | MATCH |
| 6 | `Connection: Keep-Alive` | `Connection: Keep-Alive` | MATCH |
| 7 | `Accept-Encoding: gzip` | `Accept-Encoding: gzip` | MATCH |
| 8 | `Content-Length: 1124` | `Content-Length: 1124` | MATCH |

Headers: names, order and values all MATCH.  <!--HDR_OK:42-->

**Field order (golden vs ours)**

Field NAME SEQUENCE: **DIFFERS**.

| pos | golden | ours |
|---|---|---|
| 1 | store_name_from_system | store_name_from_system |
| 2 | gps_adid_attempt | gps_adid_attempt |
| 3 | country | country |
| 4 | api_level | api_level |
| 5 | hardware_name | hardware_name |
| 6 | partner_params | app_version | <-- DIFF
| 7 | app_version | app_token | <-- DIFF
| 8 | app_token | installed_at | <-- DIFF
| 9 | installed_at | created_at | <-- DIFF
| 10 | created_at | wait_total | <-- DIFF
| 11 | wait_total | device_type | <-- DIFF
| 12 | device_type | language | <-- DIFF
| 13 | language | gps_adid | <-- DIFF
| 14 | gps_adid | foreground | <-- DIFF
| 15 | foreground | connectivity_type | <-- DIFF
| 16 | connectivity_type | device_manufacturer | <-- DIFF
| 17 | device_manufacturer | display_width | <-- DIFF
| 18 | display_width | device_name | <-- DIFF
| 19 | device_name | needs_response_details | <-- DIFF
| 20 | needs_response_details | os_build | <-- DIFF
| 21 | os_build | updated_at | <-- DIFF
| 22 | updated_at | cpu_type | <-- DIFF
| 23 | cpu_type | retry_count | <-- DIFF
| 24 | retry_count | screen_size | <-- DIFF
| 25 | screen_size | screen_format | <-- DIFF
| 26 | screen_format | last_error | <-- DIFF
| 27 | last_error | gps_adid_src | <-- DIFF
| 28 | gps_adid_src | wait_time | <-- DIFF
| 29 | wait_time | os_version | <-- DIFF
| 30 | os_version | first_error | <-- DIFF
| 31 | first_error | partner_params | <-- DIFF
| 32 | android_uuid | initiating_package_name | <-- DIFF
| 33 | sent_at | android_uuid | <-- DIFF
| 34 | offline_mode_enabled | sent_at | <-- DIFF
| 35 | environment | offline_mode_enabled | <-- DIFF
| 36 | screen_density | environment | <-- DIFF
| 37 | attribution_deeplink | screen_density | <-- DIFF
| 38 | session_count | attribution_deeplink | <-- DIFF
| 39 | display_height | session_count | <-- DIFF
| 40 | package_name | display_height | <-- DIFF
| 41 | initiating_package_name | package_name | <-- DIFF
| 42 | os_name | os_name |
| 43 | ui_mode | ui_mode |
| 44 | enqueue_size | enqueue_size |
| 45 | tracking_enabled | tracking_enabled |

Minimal order diffs (root causes):
- golden places [partner_params] at golden pos 6 (right after `hardware_name`) -- ours does not
- ours injects [partner_params, initiating_package_name] (our pos 31) where the golden has nothing -- not in the golden
- golden places [initiating_package_name] at golden pos 41 (right after `package_name`) -- ours does not

**Field set**: golden 45, ours 45, common 45.

**Values** (per-install fields whitelisted)

| field | golden | ours | verdict |
|---|---|---|---|
| store_name_from_system | `com.android.vending` | `com.android.vending` | MATCH |
| gps_adid_attempt | `1` | `1` | MATCH |
| country | `IN` | `IN` | MATCH |
| api_level | `31` | `31` | MATCH |
| hardware_name | `S2SE32.28-28-4` | `S2SE32.28-28-4` | MATCH |
| partner_params | `{"payrupik_c_id":"4c2576c7-56da-3568-9d9c-dd` | `{"payrupik_c_id":"4c2576c7-56da-3568-9d9c-dd` | PER-INSTALL |
| app_version | `3.0.4` | `3.0.4` | MATCH |
| app_token | `smxi7gqwu39c` | `smxi7gqwu39c` | MATCH |
| installed_at | `2026-10-06T15:41:06.629Z+0530` | `2026-10-06T21:46:17.800Z+0530` | PER-INSTALL (click+41s vs click+63s) |
| created_at | `2026-10-06T15:47:38.430Z+0530` | `2026-10-06T21:52:27.198Z+0530` | PER-INSTALL (click+433s vs click+433s) |
| wait_total | `0.0` | `0.0` | MATCH |
| device_type | `phone` | `phone` | MATCH |
| language | `en` | `en` | MATCH |
| gps_adid | `0a5863d0-66f6-4d15-b9ab-d388b77c8ba3` | `264fd707-78ca-4f46-8c87-e63d106de56f` | PER-INSTALL |
| foreground | `1` | `1` | MATCH |
| connectivity_type | `1` | `1` | MATCH |
| device_manufacturer | `motorola` | `motorola` | MATCH |
| display_width | `1080` | `1080` | MATCH |
| device_name | `moto g42` | `moto g42` | MATCH |
| needs_response_details | `1` | `1` | MATCH |
| os_build | `S2SE32.28-28-4` | `S2SE32.28-28-4` | MATCH |
| updated_at | `2026-10-06T15:41:06.629Z+0530` | `2026-10-06T21:46:17.800Z+0530` | PER-INSTALL (click+41s vs click+63s) |
| cpu_type | `arm64-v8a` | `arm64-v8a` | MATCH |
| retry_count | `0` | `0` | MATCH |
| screen_size | `normal` | `normal` | MATCH |
| screen_format | `long` | `long` | MATCH |
| last_error | `0` | `0` | MATCH |
| gps_adid_src | `service` | `service` | MATCH |
| wait_time | `0.0` | `0.0` | MATCH |
| os_version | `12` | `12` | MATCH |
| first_error | `0` | `0` | MATCH |
| android_uuid | `bd338228-9793-4b65-a4c6-2cc461e2801f` | `5bab7408-a750-42ba-a624-7297390eb3d3` | PER-INSTALL |
| sent_at | `2026-10-06T15:47:38.514Z+0530` | `2026-10-06T21:52:27.523Z+0530` | PER-INSTALL (click+433s vs click+433s) |
| offline_mode_enabled | `0` | `0` | MATCH |
| environment | `production` | `production` | MATCH |
| screen_density | `high` | `high` | MATCH |
| attribution_deeplink | `1` | `1` | MATCH |
| session_count | `1` | `1` | MATCH |
| display_height | `2237` | `2400` | **VALUE DIFF (structural)** `2237` vs `2400` |
| package_name | `in.hanafintech` | `in.hanafintech` | MATCH |
| initiating_package_name | `com.android.vending` | `com.android.vending` | MATCH |
| os_name | `android` | `android` | MATCH |
| ui_mode | `1` | `1` | MATCH |
| enqueue_size | `0` | `0` | MATCH |
| tracking_enabled | `1` | `1` | MATCH |

**Raw percent-encoded body after masking per-install values** (timestamps, uuids, reftag):
- **DIFFERS** (golden 1124 B, ours 1124 B; first masked-byte divergence at offset 115).
- golden: `...i_level=31&hardware_name=S2SE32.28-28-4&partner_params=%7B%22payrupik_c_id%22%3A%22<UUID>%22%7D&app_`
- ours  : `...i_level=31&hardware_name=S2SE32.28-28-4&app_version=3.0.4&app_token=smxi7gqwu39c&installed_at=<TS>&c`

**Encoding re-check** (golden raw token == re-encoded decoded value under call()'s scheme):
- all 45 golden field values re-encode byte-identically under call()'s scheme (urlencode/quote_plus) -- no +/%20/%3A/%2B encoding diffs.

chls cross-check: chls order minus its push_token is IDENTICAL to the saz golden order -- the two captures agree; push_token presence is device-state (Pixel 6a had an FCM token, the moto g42 golden has none anywhere).

---

## Endpoint POST /sdk_click

**Request line**
- golden : `POST https://app.adjust.com/sdk_click HTTP/1.1`
- ours   : `POST /sdk_click HTTP/1.1`
- absolute-form URI in the golden = capture-through-CONNECT-proxy artifact (Fiddler); a direct Dalvik call sends origin-form. Expected difference, not a device behaviour diff.

**Headers (names, order, values)**

| # | golden | ours (call()) | verdict |
|---|---|---|---|
| 1 | `Client-SDK: android5.6.0` | `Client-SDK: android5.6.0` | MATCH |
| 2 | `Authorization: Signature signature="55DBE22A2D099DAF5368D1091190EE1` | `Authorization: <per-install signature -- format check>` | MATCH (blob 304 B, sid 1300000, alg adj7, hdr 8, nv 3.62.0) |
| 3 | `Content-Type: application/x-www-form-urlencoded` | `Content-Type: application/x-www-form-urlencoded` | MATCH |
| 4 | `User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S` | `User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S` | MATCH |
| 5 | `Host: app.adjust.com` | `Host: app.adjust.com` | MATCH |
| 6 | `Connection: Keep-Alive` | `Connection: Keep-Alive` | MATCH |
| 7 | `Accept-Encoding: gzip` | `Accept-Encoding: gzip` | MATCH |
| 8 | `Content-Length: 1420` | `Content-Length: 1420` | MATCH |

Headers: names, order and values all MATCH.  <!--HDR_OK:43-->

**Field order (golden vs ours)**

Field NAME SEQUENCE: **DIFFERS**.

| pos | golden | ours |
|---|---|---|
| 1 | country | country |
| 2 | api_level | api_level |
| 3 | hardware_name | hardware_name |
| 4 | app_version | app_version |
| 5 | partner_params | app_token | <-- DIFF
| 6 | app_token | installed_at | <-- DIFF
| 7 | installed_at | device_type | <-- DIFF
| 8 | device_type | language | <-- DIFF
| 9 | language | gps_adid | <-- DIFF
| 10 | gps_adid | source | <-- DIFF
| 11 | source | foreground | <-- DIFF
| 12 | foreground | connectivity_type | <-- DIFF
| 13 | connectivity_type | os_build | <-- DIFF
| 14 | os_build | click_time | <-- DIFF
| 15 | click_time | cpu_type | <-- DIFF
| 16 | cpu_type | install_version | <-- DIFF
| 17 | install_version | partner_params | <-- DIFF
| 18 | screen_size | click_time_server | <-- DIFF
| 19 | gps_adid_src | screen_size | <-- DIFF
| 20 | subsession_count | gps_adid_src | <-- DIFF
| 21 | sent_at | subsession_count | <-- DIFF
| 22 | offline_mode_enabled | sent_at | <-- DIFF
| 23 | screen_density | offline_mode_enabled | <-- DIFF
| 24 | session_count | screen_density | <-- DIFF
| 25 | ui_mode | session_count | <-- DIFF
| 26 | gps_adid_attempt | ui_mode | <-- DIFF
| 27 | session_length | gps_adid_attempt | <-- DIFF
| 28 | created_at | session_length | <-- DIFF
| 29 | referrer_api | created_at | <-- DIFF
| 30 | device_manufacturer | referrer_api | <-- DIFF
| 31 | display_width | device_manufacturer | <-- DIFF
| 32 | time_spent | display_width | <-- DIFF
| 33 | device_name | time_spent | <-- DIFF
| 34 | needs_response_details | device_name | <-- DIFF
| 35 | updated_at | needs_response_details | <-- DIFF
| 36 | screen_format | updated_at | <-- DIFF
| 37 | click_time_server | screen_format | <-- DIFF
| 38 | os_version | os_version |
| 39 | google_play_instant | google_play_instant |
| 40 | install_begin_time_server | android_uuid | <-- DIFF
| 41 | android_uuid | referrer | <-- DIFF
| 42 | referrer | environment | <-- DIFF
| 43 | environment | attribution_deeplink | <-- DIFF
| 44 | attribution_deeplink | install_begin_time | <-- DIFF
| 45 | install_begin_time | install_begin_time_server | <-- DIFF
| 46 | display_height | display_height |
| 47 | package_name | package_name |
| 48 | os_name | os_name |
| 49 | tracking_enabled | tracking_enabled |

Minimal order diffs (root causes):
- golden places [partner_params] at golden pos 5 (right after `app_version`) -- ours does not
- ours injects [partner_params, click_time_server] (our pos 17) where the golden has nothing -- not in the golden
- golden places [click_time_server] at golden pos 37 (right after `screen_format`) -- ours does not
- golden places [install_begin_time_server] at golden pos 40 (right after `google_play_instant`) -- ours does not
- ours injects [install_begin_time_server] (our pos 45) where the golden has nothing -- not in the golden

**Field set**: golden 49, ours 49, common 49.

**Values** (per-install fields whitelisted)

| field | golden | ours | verdict |
|---|---|---|---|
| country | `IN` | `IN` | MATCH |
| api_level | `31` | `31` | MATCH |
| hardware_name | `S2SE32.28-28-4` | `S2SE32.28-28-4` | MATCH |
| app_version | `3.0.4` | `3.0.4` | MATCH |
| partner_params | `{"payrupik_c_id":"4c2576c7-56da-3568-9d9c-dd` | `{"payrupik_c_id":"4c2576c7-56da-3568-9d9c-dd` | PER-INSTALL |
| app_token | `smxi7gqwu39c` | `smxi7gqwu39c` | MATCH |
| installed_at | `2026-10-06T15:41:06.629Z+0530` | `2026-10-06T21:46:17.800Z+0530` | PER-INSTALL (click+41s vs click+63s) |
| device_type | `phone` | `phone` | MATCH |
| language | `en` | `en` | MATCH |
| gps_adid | `0a5863d0-66f6-4d15-b9ab-d388b77c8ba3` | `264fd707-78ca-4f46-8c87-e63d106de56f` | PER-INSTALL |
| source | `install_referrer` | `install_referrer` | MATCH |
| foreground | `1` | `1` | MATCH |
| connectivity_type | `1` | `1` | MATCH |
| os_build | `S2SE32.28-28-4` | `S2SE32.28-28-4` | MATCH |
| click_time | `2026-10-06T15:40:25.000Z+0530` | `2026-10-06T21:45:14.000Z+0530` | PER-INSTALL (click+0s vs click+0s) |
| cpu_type | `arm64-v8a` | `arm64-v8a` | MATCH |
| install_version | `3.0.4` | `3.0.4` | MATCH |
| screen_size | `normal` | `normal` | MATCH |
| gps_adid_src | `service` | `service` | MATCH |
| subsession_count | `1` | `1` | MATCH |
| sent_at | `2026-10-06T15:47:38.545Z+0530` | `2026-10-06T21:52:27.263Z+0530` | PER-INSTALL (click+433s vs click+433s) |
| offline_mode_enabled | `0` | `0` | MATCH |
| screen_density | `high` | `high` | MATCH |
| session_count | `1` | `1` | MATCH |
| ui_mode | `1` | `1` | MATCH |
| gps_adid_attempt | `1` | `1` | MATCH |
| session_length | `0` | `0` | MATCH |
| created_at | `2026-10-06T15:47:38.531Z+0530` | `2026-10-06T21:52:27.252Z+0530` | PER-INSTALL (click+433s vs click+433s) |
| referrer_api | `google` | `google` | MATCH |
| device_manufacturer | `motorola` | `motorola` | MATCH |
| display_width | `1080` | `1080` | MATCH |
| time_spent | `0` | `0` | MATCH |
| device_name | `moto g42` | `moto g42` | MATCH |
| needs_response_details | `1` | `1` | MATCH |
| updated_at | `2026-10-06T15:41:06.629Z+0530` | `2026-10-06T21:46:17.800Z+0530` | PER-INSTALL (click+41s vs click+63s) |
| screen_format | `long` | `long` | MATCH |
| click_time_server | `2026-10-06T15:40:25.000Z+0530` | `2026-10-06T21:45:14.000Z+0530` | PER-INSTALL (click+0s vs click+0s) |
| os_version | `12` | `12` | MATCH |
| google_play_instant | `0` | `0` | MATCH |
| install_begin_time_server | `2026-10-06T15:40:26.000Z+0530` | `2026-10-06T21:45:16.000Z+0530` | PER-INSTALL (click+1s vs click+2s) (golden = click+1 s; ours = click+2 s) |
| android_uuid | `bd338228-9793-4b65-a4c6-2cc461e2801f` | `5bab7408-a750-42ba-a624-7297390eb3d3` | PER-INSTALL |
| referrer | `adjust_reftag=c4s6jwfH2OB7q&utm_source=VL-Al` | `adjust_reftag=cKNcfOETAUh5b&utm_source=VL-Al` | PER-INSTALL |
| environment | `production` | `production` | MATCH |
| attribution_deeplink | `1` | `1` | MATCH |
| install_begin_time | `2026-10-06T15:40:26.000Z+0530` | `2026-10-06T21:45:16.000Z+0530` | PER-INSTALL (click+1s vs click+2s) (golden = click+1 s; ours = click+2 s) |
| display_height | `2237` | `2400` | **VALUE DIFF (structural)** `2237` vs `2400` |
| package_name | `in.hanafintech` | `in.hanafintech` | MATCH |
| os_name | `android` | `android` | MATCH |
| tracking_enabled | `1` | `1` | MATCH |

**Raw percent-encoded body after masking per-install values** (timestamps, uuids, reftag):
- **DIFFERS** (golden 1420 B, ours 1420 B; first masked-byte divergence at offset 71).
- golden: `...e_name=S2SE32.28-28-4&app_version=3.0.4&partner_params=%7B%22payrupik_c_id%22%3A%22<UUID>%22%7D&app_`
- ours  : `...e_name=S2SE32.28-28-4&app_version=3.0.4&app_token=smxi7gqwu39c&installed_at=<TS>&device_type=phone&l`

**Encoding re-check** (golden raw token == re-encoded decoded value under call()'s scheme):
- all 49 golden field values re-encode byte-identically under call()'s scheme (urlencode/quote_plus) -- no +/%20/%3A/%2B encoding diffs.

chls cross-check: chls order minus its push_token is IDENTICAL to the saz golden order -- the two captures agree; push_token presence is device-state (Pixel 6a had an FCM token, the moto g42 golden has none anywhere).

---

## Endpoint GET /attribution

**Request line**
- golden : `GET https://app.adjust.com/attribution?initiated_by=backend&gps_adid_attempt=1&api_level=31&app_version=3.0.4&app_token=smxi7gqwu39c&os_version=12&created_at=2026-10-06T15%3A47%3A41.741Z%2B0530&device_type=phone&gps_adid=0a5863d0-66f6-4d15-b9ab-d388b77c8ba3&foreground=1&android_uuid=bd338228-9793-4b65-a4c6-2cc461e2801f&sent_at=2026-10-06T15%3A47%3A41.754Z%2B0530&offline_mode_enabled=0&device_name=moto%20g42&environment=production&needs_response_details=1&attribution_deeplink=1&package_name=in.hanafintech&os_name=android&ui_mode=1&gps_adid_src=service&tracking_enabled=1 HTTP/1.1`
- ours   : `GET /attribution?initiated_by=backend&gps_adid_attempt=1&api_level=31&app_version=3.0.4&app_token=smxi7gqwu39c&os_version=12&created_at=2026-10-06T21%3A52%3A30.539Z%2B0530&device_type=phone&gps_adid=264fd707-78ca-4f46-8c87-e63d106de56f&foreground=1&android_uuid=5bab7408-a750-42ba-a624-7297390eb3d3&sent_at=2026-10-06T21%3A52%3A30.569Z%2B0530&offline_mode_enabled=0&device_name=moto%20g42&environment=production&needs_response_details=1&attribution_deeplink=1&package_name=in.hanafintech&os_name=android&ui_mode=1&gps_adid_src=service&push_token=f0123456789Zx_9R7cQ8yY%3AAPA91bH0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&tracking_enabled=1 HTTP/1.1`
- absolute-form URI in the golden = capture-through-CONNECT-proxy artifact (Fiddler); a direct Dalvik call sends origin-form. Expected difference, not a device behaviour diff.

**Headers (names, order, values)**

| # | golden | ours (call()) | verdict |
|---|---|---|---|
| 1 | `Client-SDK: android5.6.0` | `Client-SDK: android5.6.0` | MATCH |
| 2 | `Authorization: Signature signature="29FC17E923F797F0074FC8914ED7FCB` | `Authorization: <per-install signature -- format check>` | MATCH (blob 304 B, sid 1300000, alg adj7, hdr 8, nv 3.62.0) |
| 3 | `User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S` | `User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S` | MATCH |
| 4 | `Host: app.adjust.com` | `Host: app.adjust.com` | MATCH |
| 5 | `Connection: Keep-Alive` | `Connection: Keep-Alive` | MATCH |
| 6 | `Accept-Encoding: gzip` | `Accept-Encoding: gzip` | MATCH |

Headers: names, order and values all MATCH.  <!--HDR_OK:44-->

**Field order (golden vs ours)**

Field NAME SEQUENCE: **DIFFERS**.

| pos | golden | ours |
|---|---|---|
| 1 | initiated_by | initiated_by |
| 2 | gps_adid_attempt | gps_adid_attempt |
| 3 | api_level | api_level |
| 4 | app_version | app_version |
| 5 | app_token | app_token |
| 6 | os_version | os_version |
| 7 | created_at | created_at |
| 8 | device_type | device_type |
| 9 | gps_adid | gps_adid |
| 10 | foreground | foreground |
| 11 | android_uuid | android_uuid |
| 12 | sent_at | sent_at |
| 13 | offline_mode_enabled | offline_mode_enabled |
| 14 | device_name | device_name |
| 15 | environment | environment |
| 16 | needs_response_details | needs_response_details |
| 17 | attribution_deeplink | attribution_deeplink |
| 18 | package_name | package_name |
| 19 | os_name | os_name |
| 20 | ui_mode | ui_mode |
| 21 | gps_adid_src | gps_adid_src |
| 22 | tracking_enabled | push_token | <-- DIFF
| 23 | - | tracking_enabled | <-- DIFF

EXTRA fields (ours only): ['push_token']

Minimal order diffs (root causes):
- ours injects [push_token] (our pos 22) where the golden has nothing -- not in the golden

**Field set**: golden 22, ours 23, common 22.

**Values** (per-install fields whitelisted)

| field | golden | ours | verdict |
|---|---|---|---|
| initiated_by | `backend` | `backend` | MATCH |
| gps_adid_attempt | `1` | `1` | MATCH |
| api_level | `31` | `31` | MATCH |
| app_version | `3.0.4` | `3.0.4` | MATCH |
| app_token | `smxi7gqwu39c` | `smxi7gqwu39c` | MATCH |
| os_version | `12` | `12` | MATCH |
| created_at | `2026-10-06T15:47:41.741Z+0530` | `2026-10-06T21:52:30.539Z+0530` | PER-INSTALL (click+436s vs click+436s) |
| device_type | `phone` | `phone` | MATCH |
| gps_adid | `0a5863d0-66f6-4d15-b9ab-d388b77c8ba3` | `264fd707-78ca-4f46-8c87-e63d106de56f` | PER-INSTALL |
| foreground | `1` | `1` | MATCH |
| android_uuid | `bd338228-9793-4b65-a4c6-2cc461e2801f` | `5bab7408-a750-42ba-a624-7297390eb3d3` | PER-INSTALL |
| sent_at | `2026-10-06T15:47:41.754Z+0530` | `2026-10-06T21:52:30.569Z+0530` | PER-INSTALL (click+436s vs click+436s) |
| offline_mode_enabled | `0` | `0` | MATCH |
| device_name | `moto g42` | `moto g42` | MATCH |
| environment | `production` | `production` | MATCH |
| needs_response_details | `1` | `1` | MATCH |
| attribution_deeplink | `1` | `1` | MATCH |
| package_name | `in.hanafintech` | `in.hanafintech` | MATCH |
| os_name | `android` | `android` | MATCH |
| ui_mode | `1` | `1` | MATCH |
| gps_adid_src | `service` | `service` | MATCH |
| tracking_enabled | `1` | `1` | MATCH |

**Raw percent-encoded query string after masking per-install values** (timestamps, uuids, reftag):
- **DIFFERS** (golden 536 B, ours 644 B; first masked-byte divergence at offset 396).
- golden: `...=android&ui_mode=1&gps_adid_src=service&tracking_enabled=1`
- ours  : `...=android&ui_mode=1&gps_adid_src=service&push_token=f0123456789Zx_9R7cQ8yY%3AAPA91bH0123456789abcdef0`

**Encoding re-check** (golden raw token == re-encoded decoded value under call()'s scheme):
- all 22 golden field values re-encode byte-identically under call()'s scheme (urlencode/quote) -- no +/%20/%3A/%2B encoding diffs.

chls cross-check: same field SET, different ORDER (GET-map iteration differs between the two genuine runs) -- saz is primary.

---

## Endpoint POST /event

**Request line**
- golden : `POST https://app.adjust.com/event HTTP/1.1`
- ours   : `POST /event HTTP/1.1`
- absolute-form URI in the golden = capture-through-CONNECT-proxy artifact (Fiddler); a direct Dalvik call sends origin-form. Expected difference, not a device behaviour diff.

**Headers/Body**: the funnel has NO builder for this endpoint (no POST /event in run_install.py) -- golden-only step, see findings.  (The golden headers are the same Client-SDK/Authorization/Content-Type/User-Agent/Host/Connection/Accept-Encoding/Content-Length table.)

---

## 3. SIGNED-MAP H-law re-check on the golden's signatures

cbc_dec (work/ks_inverse.py, K from work/record_0015.json) over the golden blob -> record a/b/c/d -> nonce12 -> adj7_pure.build_claims (include_block2=True, client_sdk=android5.6.0) over the golden's decoded body map -> commitment_digest == record b.

| endpoint | blob tag ok | record c == campaign cert | claims B | commitment_digest == record b | verdict |
|---|---|---|---|---|---|
| /session | ok | yes (`C1BFAFCAFFB8...`) | 383 | **MATCH** | PASS (full 304-B blob reproduced byte-exact at sec 1791281858) |
| /sdk_click | ok | yes (`C1BFAFCAFFB8...`) | 579 | **MATCH** | PASS (full 304-B blob reproduced byte-exact at sec 1791281858) |
| /attribution | ok | yes (`C1BFAFCAFFB8...`) | 211 | **MATCH** | PASS (full 304-B blob reproduced byte-exact at sec 1791281861) |
| /event | ok | yes (`C1BFAFCAFFB8...`) | 350 | **MISMATCH** | **FAIL** |

Cert prefix note: every golden record's `c` slot carries the ASCII hex-upper cert SHA-1 `C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF` -- run_install's `sign()` passes CAMPAIGN (cert_sha1 c1bfafca...) straight into mint_adj7, so the prefix wiring is correct.

---

## 4. Timing story (golden vs funnel)
- golden : click 15:40:25 -> installed_at click+41.6 s -> session click+433 s -> sdk_click +0.0 ms -> attribution click+436 s -> event click+438 s
- funnel : installed_at click+63.800 s (INSTALL_AFTER=63.8, from the chls capture) -> session click+88 s (wall-clock CTIT) -> sdk_click +50 ms -> attribution ~click+91 s (sleep 2.8)
- verdict : relative gaps are per-install values. The funnel reproduces the chls story (click+63.8 install, click+88.3 session); the golden capture's own story is click+41.6 install, click+433 session. Both are plausible human installs; CTIT >> 10 s in both. No structural impact -- but see the install_begin_time note.

---

## 5. Structural findings (must-fix before the live run)

1. /session: ORDER -- golden places [partner_params] at golden pos 6 (right after `hardware_name`) -- ours does not; ours injects [partner_params, initiating_package_name] (our pos 31) where the golden has nothing -- not in the golden; golden places [initiating_package_name] at golden pos 41 (right after `package_name`) -- ours does not
2. run_install.py build_session_request: display_height value `2400` but the golden device sends `2237`
3. /sdk_click: ORDER -- golden places [partner_params] at golden pos 5 (right after `app_version`) -- ours does not; ours injects [partner_params, click_time_server] (our pos 17) where the golden has nothing -- not in the golden; golden places [click_time_server] at golden pos 37 (right after `screen_format`) -- ours does not; golden places [install_begin_time_server] at golden pos 40 (right after `google_play_instant`) -- ours does not; ours injects [install_begin_time_server] (our pos 45) where the golden has nothing -- not in the golden
4. run_install.py build_click_request: display_height value `2400` but the golden device sends `2237`
5. /attribution: ORDER -- ours injects [push_token] (our pos 22) where the golden has nothing -- not in the golden

### Precise fixes
1. `adj7/run_install.py` `build_session_request` (lines 305-330; partner_params at line 322, initiating_package_name at line 323): move `"partner_params": PARTNER_PARAMS` from its current position (after `first_error`, pos 31) to immediately after `"hardware_name"` (pos 6, before `"app_version"`); move `"initiating_package_name"` from after `partner_params` to immediately after `"package_name"` (before `"os_name"`).  Golden order: ... first_error, android_uuid, sent_at ... display_height, package_name, initiating_package_name, os_name ...
2. `adj7/run_install.py` `build_click_request` (lines 272-299; partner_params at line 280, click_time_server at line 281, install_begin_time_server at line 296): move `"partner_params"` to immediately after `"app_version"` (pos 5, before `"app_token"`); move `"click_time_server"` to immediately after `"screen_format"` (pos 37, before `"os_version"`); move `"install_begin_time_server"` to immediately after `"google_play_instant"` (pos 40, before `"android_uuid"`); keep `"install_begin_time"` after `"attribution_deeplink"`.  After removal of the two misplacements the tail order matches the golden exactly.
3. `adj7/run_install.py` `build_attribution_request` (line 345): DELETE the `"push_token": PUSH_TOKEN` entry (22 params, not 23).  The golden moto g42 capture carries NO push_token on ANY request (session/sdk_click/attribution/event); push_token is Pixel-6a/chls device state.  (The saz is primary per the brief.)
4. `adj7/run_install.py` `DEVICE` (line 58): `"display_height": "2400"` -> `"2237"`.  The golden moto g42 reports display_height=2237 (2400 panel minus system bars) on session, sdk_click and event; 2400 is the chls Pixel 6a's value.
5. (recommended) `build_click_request`: `begin = click_sec + 2` -> `click_sec + 1` (line 271).  Golden: click 15:40:25.000 -> install_begin 15:40:26.000; the funnel stamps +2 s.

---

## 6. Post-fix simulation (section-5 fixes applied to an in-memory copy of run_install.py)

Applied textual fixes:

- click: partner_params -> after app_version; click_time_server -> after screen_format; install_begin_time_server -> after google_play_instant
- session: partner_params -> after hardware_name; initiating_package_name -> after package_name
- attribution: push_token removed
- DEVICE display_height 2400 -> 2237

Re-diff of the PATCHED builders against the golden:
- POST /session: order IDENTICAL; non-install values all MATCH; masked raw **BYTE-IDENTICAL**
- POST /sdk_click: order IDENTICAL; non-install values all MATCH; masked raw **BYTE-IDENTICAL**
- GET /attribution: order IDENTICAL; non-install values all MATCH; masked raw **BYTE-IDENTICAL**

**Result: after the four fixes the patched builders reproduce the golden byte-for-byte modulo per-install values (uuids/timestamps/reftag) -- fixes verified sufficient and complete.**

---

## 7. VERDICT

- Headers: all match
- H-law on the funnel's signed endpoints (/session, /sdk_click, /attribution), CURRENT claims law over the golden's real maps: ALL PASS -- the signer is clean
- (POST /event H-law: H MISMATCH, full-blob no -- informational only, the funnel builds/signs no event.)
- Structural body diffs (root causes): 5
- Post-fix simulation (section 6): fixes verified SUFFICIENT -- patched builders reproduce the golden byte-for-byte modulo per-install values

## **NO-GO for the live run** -- apply fixes 1-4 of section 5 (5 recommended; all four already verified sufficient by the section-6 simulation), re-run final_check.py, expect zero structural diffs, then GO.

### Non-blocking observations
1. /sdk_click: install_begin_time_server offset click+2 s (golden click+1 s) -- recommend begin = click_sec + 1
2. /sdk_click: install_begin_time offset click+2 s (golden click+1 s) -- recommend begin = click_sec + 1
3. golden flow ends with POST /event (event_token y3sjx5, callback_params google_adid) 2 s after the attribution; run_install.py never sends an event. Post-verdict step (the booked verdict arrives on the attribution GET), so not a booking blocker.
4. POST /event (golden-only step): its H does NOT reproduce under our pool law over the wire map (tag/record fine, H mismatch) -- consistent with the earlier event-claims hunt (work/proven_audit/verify_event2.py).  Informational: the funnel builds and signs no event, and the task's H-law scope is session/sdk_click/attribution, which all PASS.
