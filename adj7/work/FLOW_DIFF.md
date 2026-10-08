# FLOW_DIFF.md -- genuine payrupi.chls vs our adj7 funnel (in.hanafintech)

Genuine capture: `C:\Users\Apps\Downloads\payrupi.chls` (2026-10-06, in.hanafintech 3.0.4,
adj7 / signing id 1300000 / headers_id 8 / native 3.62.0, device Pixel 6a, Android 17, tz +0530, country AE).
Our run: `adj7/run_hanaf.log` (CAMPAIGN=hanafintech, device profile = niri OnePlus 7 GM1901,
Android 10, tz +0000, country IN, mcc 405 / mnc 872).

Genuine handle-map verification: ok (10 strings, positions monotonic vs handles)

## 0. FLOW ORDER -- the single biggest difference

| # | genuine (chls) | ours (run_hanaf.log) |
|---|----------------|-----------------------|
| 1 | (click via **payrupik.go.link** -> Play Store; click itself NOT captured -- happened before the capture started; Play InstallReferrer API delivered the reftag: `referrer_api=google` in sdk_click) | click-chain hop0 `clicks.mobpine.com` 302 -> hop1 `app.adjust.com/2015o4dz` 302 -> `market://details?id=in.hanafintech&referrer=adjust_reftag=cG6ylBNe0M6tC...` |
| 2 | **POST /session** (created the adid; response carries `ask_in:2000`) | **POST /third_party_sharing** (`device not found`) -- genuine capture has **NO third_party_sharing at all** |
| 3 | **POST /sdk_click** (49 ms after session; response returns the SAME adid) | **POST /sdk_click** (creates the adid) |
| 4 | **GET /attribution** exactly once, `initiated_by=backend`, ~2.8 s after the session response (the `ask_in:2000` contract); answer = **VL-Alliance 248wk8ym on the FIRST try** | **POST /session** |
| 5 | **POST /event** (event_token y3sjx5, callback_params {google_adid}, seq=1, session_length=5, time_spent=5) ~2.1 s after the attribution answer | GET /attribution polled 4x (+30/+45/+60/+60 s), `initiated_by=sdk`, no push_token -- Organic every time |
| 6 | -- | (no event) |

Wall clock (Charles timing blocks, epoch ms):

| request | genuine Charles start | body created_at (+0530) | ours (wall, log) |
|---------|----------------------|--------------------------|------------------|
| /session | 06:25:42.822Z (UTC) | 2026-10-06T11:55:42.321Z+0530 | 12:13:00 |
| /sdk_click | 06:25:42.927Z (UTC) | 2026-10-06T11:55:42.370Z+0530 | 12:12:56 |
| /attribution | 06:25:45.238Z (UTC) | 2026-10-06T11:55:45.180Z+0530 | 12:13:30 |
| /event | 06:25:47.356Z (UTC) | 2026-10-06T11:55:47.285Z+0530 | -- |

Genuine timing relations (all +0530):

| relation | delta |
|----------|-------|
| click_time -> click_time_server | server -1.000 s (Play InstallReferrer seconds precision) |
| click_time -> install_begin_time | +1.000 s |
| click_time -> **installed_at** (CTIT, first open) | **+63.820 s** |
| installed_at -> session created_at (first open -> SDK init done) | +24.501 s |
| click_time -> session Charles start (REAL wall clock) | **+88.8 s** |
| session created_at -> sdk_click created_at | +0.049 s |
| session sent_at -> attribution created_at | +2.824 s (ask_in=2000) |
| attribution sent_at -> event created_at | +2.095 s |

OUR run timing (from the log; wire stamps +0000, wall clock = log stamps):

| relation | delta | verdict |
|----------|-------|---------|
| click -> sdk_click created_at | ~+0.25 s | genuine: +88.4 s (sdk_click fires at FIRST OPEN, not at click time) |
| click -> session created_at | ~+4.2 s | genuine: +88.3 s |
| click -> installed_at (FIELD VALUE) | +63.6 s | **installed_at lands ~59 s AFTER the session that reports it -- impossible story** |
| session -> attribution GET | +30 s .. +3.5 min | genuine: +2.8 s, once |

Timestamp FORMAT check: genuine `2026-10-06T11:55:42.321Z+0530` vs ours
`2026-10-06T06:42:55.198Z+0000` -- identical wire shape `YYYY-MM-DDTHH:MM:SS.mmmZ<tz>`;
only the tz LABEL differs (the genuine device ran +0530, our profile stamps +0000).

RESPONSES (both sides got HTTP 200 everywhere):

| endpoint | genuine response | our response |
|----------|------------------|--------------|
| third_party_sharing | (request absent) | `device not found` (expected on a fresh GAID) |
| session | `{app_token, adid, ask_in:2000}` | `{app_token, adid, ask_in:2000}` -- **we receive the same ask_in contract but ignore it** |
| sdk_click | `{app_token, adid}` (same adid -- device already existed via session) | `{app_token, adid}` (adid created HERE) |
| attribution | **non-organic**: tracker 248wk8ym `VL-Alliance::HM2::HM2_1722_`, engagement 06:24:12Z, first try | Organic every poll |
| event | 200 | (request absent) |

## 1. POST /session -- field-by-field (wire order)

Genuine (46 fields, Content-Length 1280):

```
   1. store_name_from_system       = com.android.vending
   2. gps_adid_attempt             = 1
   3. country                      = AE
   4. api_level                    = 37
   5. hardware_name                = CP2A.260705.006
   6. partner_params               = {"payrupik_c_id":"f9a63983-c27d-33e2-a9bb-fc10b7e58a51"}
   7. app_version                  = 3.0.4
   8. app_token                    = smxi7gqwu39c
   9. installed_at                 = 2026-10-06T11:55:17.820Z+0530
  10. created_at                   = 2026-10-06T11:55:42.321Z+0530
  11. wait_total                   = 0.0
  12. device_type                  = phone
  13. language                     = en
  14. gps_adid                     = 39daafc6-f5c4-412d-bf0c-e4b9482547ca
  15. foreground                   = 1
  16. connectivity_type            = 1
  17. device_manufacturer          = Google
  18. display_width                = 1080
  19. device_name                  = Pixel 6a
  20. needs_response_details       = 1
  21. os_build                     = CP2A.260705.006
  22. updated_at                   = 2026-10-06T11:55:17.820Z+0530
  23. cpu_type                     = arm64-v8a
  24. retry_count                  = 0
  25. screen_size                  = normal
  26. screen_format                = long
  27. last_error                   = 0
  28. gps_adid_src                 = service
  29. push_token                   = elO_UX5cR66PO8ev_8y9TV:APA91bE3H2KMFD0rrse1-qJqYYLhT2Qz2ht0bO8RgzJytclm7LqYqZ9uVpSHFNrnK8GAVljnB4...
  30. wait_time                    = 0.0
  31. os_version                   = 17
  32. first_error                  = 0
  33. android_uuid                 = d5c688a4-27a0-4218-af7e-2efb1a21d89e
  34. sent_at                      = 2026-10-06T11:55:42.356Z+0530
  35. offline_mode_enabled         = 0
  36. environment                  = production
  37. screen_density               = high
  38. attribution_deeplink         = 1
  39. session_count                = 1
  40. display_height               = 2400
  41. package_name                 = in.hanafintech
  42. initiating_package_name      = com.android.vending
  43. os_name                      = android
  44. ui_mode                      = 1
  45. enqueue_size                 = 0
  46. tracking_enabled             = 1
```

Diff vs ours (46 fields):

| class | fields |
|-------|--------|
| (a) genuine sends, WE OMIT | **partner_params**, **push_token**, **initiating_package_name** |
| (b) WE send, genuine omits | **mcc**, **mnc**, **queue_size** |
| value differences in common fields | **country** [geo profile]: genuine `AE` vs ours `IN`; **api_level** [device profile]: genuine `37` vs ours `29`; **hardware_name** [device profile]: genuine `CP2A.260705.006` vs ours `GM1901_14_201019`; **installed_at** [story/semantic]: genuine `2026-10-06T11:55:17.820Z+0530` vs ours `2026-10-06T06:43:54.591Z+0000`; **created_at** [per-run identity]: genuine `2026-10-06T11:55:42.321Z+0530` vs ours `2026-10-06T06:42:55.198Z+0000`; **gps_adid** [per-run identity]: genuine `39daafc6-f5c4-412d-bf0c-e4b9482547ca` vs ours `3f7a21f1-d4ab-406d-95f2-0643e15099a9`; **device_manufacturer** [device profile]: genuine `Google` vs ours `OnePlus`; **device_name** [device profile]: genuine `Pixel 6a` vs ours `GM1901`; **os_build** [device profile]: genuine `CP2A.260705.006` vs ours `QKQ1.190716.003`; **updated_at** [story/semantic]: genuine `2026-10-06T11:55:17.820Z+0530` vs ours `2026-10-06T06:43:54.591Z+0000`; **os_version** [device profile]: genuine `17` vs ours `10`; **android_uuid** [per-run identity]: genuine `d5c688a4-27a0-4218-af7e-2efb1a21d89e` vs ours `c9cedf06-7a04-42a9-a568-4af45638dd4d`; **sent_at** [per-run identity]: genuine `2026-10-06T11:55:42.356Z+0530` vs ours `2026-10-06T06:42:55.523Z+0000`; **display_height** [device profile]: genuine `2400` vs ours `2218` |
| relative order of the common fields | IDENTICAL |

Notes:

* `push_token` -- Firebase/FCM InstanceID token (`<22 chars>:APA91b...`). The SDK has it before ANY server
  response (it is already in the FIRST request = session), so it comes from Firebase, not from Adjust.
  It is missing from every request we send (session, sdk_click, attribution query).
* `partner_params` -- the APP sets `{"payrupik_c_id":"<uuid4>"}`. We never send it (session/sdk_click/event).
* `initiating_package_name=com.android.vending` -- genuine session carries it IN ADDITION to
  `store_name_from_system=com.android.vending`; we only send the latter (came from the niri capture).
* `mcc`/`mnc`/`queue_size` -- WE ADD these (niri-capture leftovers); the genuine hanafintech 3.62.0
  session has neither mcc/mnc nor queue_size.
* `installed_at` = 11:55:17.820 = click + 63.82 s = FIRST OPEN (== updated_at), i.e. BEFORE the session's
  created_at (11:55:42.321) by 24.5 s. Ours has installed_at = click + 63 s but created_at = click + 4 s --
  the session claims to run a minute BEFORE its own install moment.

## 2. POST /sdk_click -- field-by-field (wire order)

Genuine (50 fields, Content-Length 1576):

```
   1. country                      = AE
   2. api_level                    = 37
   3. hardware_name                = CP2A.260705.006
   4. app_version                  = 3.0.4
   5. partner_params               = {"payrupik_c_id":"f9a63983-c27d-33e2-a9bb-fc10b7e58a51"}
   6. app_token                    = smxi7gqwu39c
   7. installed_at                 = 2026-10-06T11:55:17.820Z+0530
   8. device_type                  = phone
   9. language                     = en
  10. gps_adid                     = 39daafc6-f5c4-412d-bf0c-e4b9482547ca
  11. source                       = install_referrer
  12. foreground                   = 1
  13. connectivity_type            = 1
  14. os_build                     = CP2A.260705.006
  15. click_time                   = 2026-10-06T11:54:14.000Z+0530
  16. cpu_type                     = arm64-v8a
  17. install_version              = 3.0.4
  18. screen_size                  = normal
  19. gps_adid_src                 = service
  20. subsession_count             = 1
  21. sent_at                      = 2026-10-06T11:55:42.373Z+0530
  22. offline_mode_enabled         = 0
  23. screen_density               = high
  24. session_count                = 1
  25. ui_mode                      = 1
  26. gps_adid_attempt             = 1
  27. session_length               = 0
  28. created_at                   = 2026-10-06T11:55:42.370Z+0530
  29. referrer_api                 = google
  30. device_manufacturer          = Google
  31. display_width                = 1080
  32. time_spent                   = 0
  33. device_name                  = Pixel 6a
  34. needs_response_details       = 1
  35. updated_at                   = 2026-10-06T11:55:17.820Z+0530
  36. screen_format                = long
  37. push_token                   = elO_UX5cR66PO8ev_8y9TV:APA91bE3H2KMFD0rrse1-qJqYYLhT2Qz2ht0bO8RgzJytclm7LqYqZ9uVpSHFNrnK8GAVljnB4...
  38. click_time_server            = 2026-10-06T11:54:13.000Z+0530
  39. os_version                   = 17
  40. google_play_instant          = 0
  41. install_begin_time_server    = 2026-10-06T11:54:15.000Z+0530
  42. android_uuid                 = d5c688a4-27a0-4218-af7e-2efb1a21d89e
  43. referrer                     = adjust_reftag=cmTHC4v8KOvVM&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_
  44. environment                  = production
  45. attribution_deeplink         = 1
  46. install_begin_time           = 2026-10-06T11:54:15.000Z+0530
  47. display_height               = 2400
  48. package_name                 = in.hanafintech
  49. os_name                      = android
  50. tracking_enabled             = 1
```

Diff vs ours (47 fields):

| class | fields |
|-------|--------|
| (a) genuine sends, WE OMIT | **partner_params**, **install_version**, **push_token**, **click_time_server**, **install_begin_time_server** |
| (b) WE send, genuine omits | **mcc**, **mnc** |
| value differences in common fields | **country** [geo profile]: genuine `AE` vs ours `IN`; **api_level** [device profile]: genuine `37` vs ours `29`; **hardware_name** [device profile]: genuine `CP2A.260705.006` vs ours `GM1901_14_201019`; **installed_at** [story/semantic]: genuine `2026-10-06T11:55:17.820Z+0530` vs ours `2026-10-06T06:43:54.591Z+0000`; **gps_adid** [per-run identity]: genuine `39daafc6-f5c4-412d-bf0c-e4b9482547ca` vs ours `3f7a21f1-d4ab-406d-95f2-0643e15099a9`; **os_build** [device profile]: genuine `CP2A.260705.006` vs ours `QKQ1.190716.003`; **click_time** [story/semantic]: genuine `2026-10-06T11:54:14.000Z+0530` vs ours `2026-10-06T06:42:51.000Z+0000`; **sent_at** [per-run identity]: genuine `2026-10-06T11:55:42.373Z+0530` vs ours `2026-10-06T06:42:51.263Z+0000`; **created_at** [per-run identity]: genuine `2026-10-06T11:55:42.370Z+0530` vs ours `2026-10-06T06:42:51.252Z+0000`; **device_manufacturer** [device profile]: genuine `Google` vs ours `OnePlus`; **device_name** [device profile]: genuine `Pixel 6a` vs ours `GM1901`; **updated_at** [story/semantic]: genuine `2026-10-06T11:55:17.820Z+0530` vs ours `2026-10-06T06:43:54.591Z+0000`; **os_version** [device profile]: genuine `17` vs ours `10`; **android_uuid** [per-run identity]: genuine `d5c688a4-27a0-4218-af7e-2efb1a21d89e` vs ours `c9cedf06-7a04-42a9-a568-4af45638dd4d`; **referrer** [per-run identity]: genuine `adjust_reftag=cmTHC4v8KOvVM&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_` vs ours `adjust_reftag=cG6ylBNe0M6tC&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_zt1`; **install_begin_time** [story/semantic]: genuine `2026-10-06T11:54:15.000Z+0530` vs ours `2026-10-06T06:42:53.000Z+0000`; **display_height** [device profile]: genuine `2400` vs ours `2218` |
| relative order of the common fields | IDENTICAL |

Notes:

* `click_time_server` / `install_begin_time_server` -- the Play Store InstallReferrer API's server-side
  seconds-precision echoes (both .000); the genuine client got them from the REAL Play referrer read.
  Ours cannot have real ones; either omit both (cleaner) or keep only the client-side values.
* `install_version=3.0.4` == app_version; missing from ours.
* genuine `hardware_name=CP2A.260705.006` (== its os_build on that Pixel); ours `GM1901_14_201019` -- device-
  consistent for our profile, keep.
* genuine referrer = `adjust_reftag=cmTHC4v8KOvVM&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_`
  (tracker 248wk8ym's link, NO sub2 suffix); ours = `adjust_reftag=cG6ylBNe0M6tC&...&utm_content=HM2_1722_zt1`
  (tracker 2015o4dz via mobpine, sub2 zt1 appended). Each is internally consistent with its own click.

## 3. GET /attribution -- query params (wire order)

Genuine (23 params, ONE GET):

```
   1. gps_adid_attempt             = 1
   2. api_level                    = 37
   3. app_version                  = 3.0.4
   4. app_token                    = smxi7gqwu39c
   5. created_at                   = 2026-10-06T11:55:45.180Z+0530
   6. device_type                  = phone
   7. gps_adid                     = 39daafc6-f5c4-412d-bf0c-e4b9482547ca
   8. foreground                   = 1
   9. device_name                  = Pixel 6a
  10. needs_response_details       = 1
  11. gps_adid_src                 = service
  12. push_token                   = elO_UX5cR66PO8ev_8y9TV:APA91bE3H2KMFD0rrse1-qJqYYLhT2Qz2ht0bO8RgzJytclm7LqYqZ9uVpSHFNrnK8GAVljnB4...
  13. initiated_by                 = backend
  14. os_version                   = 17
  15. android_uuid                 = d5c688a4-27a0-4218-af7e-2efb1a21d89e
  16. sent_at                      = 2026-10-06T11:55:45.190Z+0530
  17. offline_mode_enabled         = 0
  18. environment                  = production
  19. attribution_deeplink         = 1
  20. package_name                 = in.hanafintech
  21. os_name                      = android
  22. ui_mode                      = 1
  23. tracking_enabled             = 1
```

Diff vs ours (22 params):

| class | fields |
|-------|--------|
| (a) genuine sends, WE OMIT | **push_token** |
| none |
| value differences | **api_level** [device profile]: genuine `37` vs ours `29`; **created_at** [per-run identity]: genuine `2026-10-06T11:55:45.180Z+0530` vs ours `2026-10-06T06:43:28.539Z+0000`; **gps_adid** [per-run identity]: genuine `39daafc6-f5c4-412d-bf0c-e4b9482547ca` vs ours `3f7a21f1-d4ab-406d-95f2-0643e15099a9`; **device_name** [device profile]: genuine `Pixel 6a` vs ours `GM1901`; **initiated_by** [story/semantic]: genuine `backend` vs ours `sdk`; **os_version** [device profile]: genuine `17` vs ours `10`; **android_uuid** [per-run identity]: genuine `d5c688a4-27a0-4218-af7e-2efb1a21d89e` vs ours `c9cedf06-7a04-42a9-a568-4af45638dd4d`; **sent_at** [per-run identity]: genuine `2026-10-06T11:55:45.190Z+0530` vs ours `2026-10-06T06:43:28.569Z+0000` |
| param order | different (query order is HashMap-ordered server-side-irrelevant, but the genuine order is above) |

* `initiated_by=backend` (not `sdk`): the ONE genuine GET is the ask_in-scheduled callback, ~2.8 s after
  the session response. It returned the non-organic answer IMMEDIATELY -- no polling ladder exists
  (the 'second attribution' in the old extract was the same request's request-line copy).

## 4. POST /event -- genuine sends it, we never do

Genuine (44 fields, Content-Length 1270), sent 2.1 s after the attribution answer:

```
   1. country                      = AE
   2. api_level                    = 37
   3. hardware_name                = CP2A.260705.006
   4. partner_params               = {"payrupik_c_id":"f9a63983-c27d-33e2-a9bb-fc10b7e58a51"}
   5. app_version                  = 3.0.4
   6. app_token                    = smxi7gqwu39c
   7. wait_total                   = 0.0
   8. device_type                  = phone
   9. language                     = en
  10. gps_adid                     = 39daafc6-f5c4-412d-bf0c-e4b9482547ca
  11. foreground                   = 1
  12. connectivity_type            = 1
  13. os_build                     = CP2A.260705.006
  14. cpu_type                     = arm64-v8a
  15. retry_count                  = 0
  16. screen_size                  = normal
  17. gps_adid_src                 = service
  18. subsession_count             = 1
  19. wait_time                    = 0.0
  20. first_error                  = 0
  21. sent_at                      = 2026-10-06T11:55:47.306Z+0530
  22. offline_mode_enabled         = 0
  23. screen_density               = high
  24. session_count                = 1
  25. ui_mode                      = 1
  26. enqueue_size                 = 0
  27. gps_adid_attempt             = 1
  28. event_count                  = 1
  29. session_length               = 5
  30. created_at                   = 2026-10-06T11:55:47.285Z+0530
  31. device_manufacturer          = Google
  32. display_width                = 1080
  33. event_token                  = y3sjx5
  34. time_spent                   = 5
  35. device_name                  = Pixel 6a
  36. needs_response_details       = 1
  37. screen_format                = long
  38. last_error                   = 0
  39. push_token                   = elO_UX5cR66PO8ev_8y9TV:APA91bE3H2KMFD0rrse1-qJqYYLhT2Qz2ht0bO8RgzJytclm7LqYqZ9uVpSHFNrnK8GAVljnB4...
  40. seq                          = 1
  41. os_version                   = 17
  42. callback_params              = {"google_adid":"39daafc6-f5c4-412d-bf0c-e4b9482547ca"}
  43. android_uuid                 = d5c688a4-27a0-4218-af7e-2efb1a21d89e
  44. environment                  = production
  45. attribution_deeplink         = 1
  46. display_height               = 2400
  47. package_name                 = in.hanafintech
  48. os_name                      = android
  49. tracking_enabled             = 1
```

* event_token `y3sjx5`, callback_params `{"google_adid":"<gaid>"}`, seq=1, event_count=1,
  session_length=5, time_spent=5 (5 s after session start), partner_params again present.
* Post-attribution, so it did NOT influence the attribution decision -- but a genuine-equivalent flow
  includes it.

## 5. REQUEST HEADERS (from the serialised name/value ArrayLists)

Genuine POST (session/sdk_click/event), wire order:

```
1. Client-SDK: android5.6.0
2. Authorization: <304-hex Signature signature=...,adj_signing_id="1300000",algorithm="adj7",headers_id="8",native_version="3.62.0">
3. Content-Type: application/x-www-form-urlencoded
4. User-Agent: Dalvik/2.1.0 (Linux; U; Android 17; Pixel 6a Build/CP2A.260705.006)
5. Host: app.adjust.com
6. Connection: Keep-Alive
7. Accept-Encoding: gzip
8. Content-Length: 1280
```

Genuine GET (attribution), wire order:

```
1. Client-SDK: android5.6.0
2. Authorization: <304-hex Signature ...>
3. User-Agent: Dalvik/2.1.0 (Linux; U; Android 17; Pixel 6a Build/CP2A.260705.006)
4. Host: app.adjust.com
5. Connection: Keep-Alive
6. Accept-Encoding: gzip
```

Ours (run_install.call()): Client-SDK, Authorization, User-Agent, Host, [Content-Type,
Content-Length], Accept-Encoding.  Diffs:

| class | diff |
|-------|------|
| (a) missing | **Connection: Keep-Alive** -- every genuine request carries it, we never send it |
| (c) order | genuine: Client-SDK, Authorization, **Content-Type**, User-Agent, Host, Connection, Accept-Encoding, **Content-Length last**; ours: Content-Type 5th, Content-Length 6th |
| (c) shape | Client-SDK value `android5.6.0`, UA `Dalvik/2.1.0 (Linux; U; Android <v>; <dev> Build/<b>)`, Authorization shape incl. headers_id=8 / native_version=3.62.0 -- all MATCH |

## 6. THE CLICK

* Genuine capture contains **no click request at all** (the only go.link hit is the GMS Digital Asset
  Links check for `https://payrupik.go.link` -- proof the click went through the branded go.link domain
  and the Play Store; the capture started after that).
* Ours: `clicks.mobpine.com` 302 -> `app.adjust.com/2015o4dz?...&ip_address=%7Bloop_id%7D&gps_adid=<gaid>...`
  302 -> `market://...&referrer=adjust_reftag=cG6ylBNe0M6tC...`.  Diffs:
  1. **`ip_address=%7Bloop_id%7D` reaches app.adjust.com UNSUBSTITUTED** -- the mobpine `{loop_id}` macro
     is not replaced for sub2=zt1, so the click is registered with a garbage ip_address value
     (gps_adid IS properly substituted, but the click's IP context is corrupt).
  2. Our click hops present the app's **Dalvik UA + a Client-SDK header** to the tracker; a genuine
     click comes from a mobile browser (no Client-SDK, browser UA).
  3. Genuine click domain: `payrupik.go.link` (tracker 248wk8ym); ours: `app.adjust.com/2015o4dz`
     (different tracker token of the same VL-Alliance::HM2 campaign).

## 7. RANKED FIX LIST for run_install.py (builders + flow order)

1. **(e) WALL-CLOCK STORY** -- run the flow at genuine speed: sleep so that the session fires
   ~INSTALL_AFTER+25 s after the click (genuine: click +88 s), NOT +4 s.  installed_at must be
   BEFORE the session's created_at: set installed_at = click + CTIT (63 s), then open the session
   ~20-30 s later.  Today installed_at lands 59 s AFTER the session that reports it -- an impossible
   story the server can see.
2. **(e) ORDER** -- session FIRST, then sdk_click (+~50 ms), then the attribution GET, then the event.
   Drop third_party_sharing entirely (the genuine hanafintech capture has none).
3. **(a) push_token** -- fabricate a stable FCM-shaped token (`<22 id chars>:APA91b...`, per-device)
   and add it to session, sdk_click and the attribution query.
4. **(a) partner_params** -- add `partner_params={"payrupik_c_id":"<uuid4>"}` to session, sdk_click
   (position: right after hardware_name / app_version) and event.
5. **(a) initiating_package_name=com.android.vending** -- add to the session body (keep
   store_name_from_system too).
6. **(b) mcc/mnc/queue_size** -- REMOVE from session and sdk_click (genuine hanafintech 3.62.0 carries
   neither; they are niri-capture leftovers).
7. **(a) install_version** (= app_version) -- add to sdk_click after cpu_type.
8. **(a) click_time_server / install_begin_time_server** -- omit (no real Play read); keep the
   client-side click_time (.000) and install_begin_time = click+1 s.
9. **(e) attribution** -- ONE GET, `initiated_by=backend`, +push_token, fired ~2.8 s after the session
   response ( honour ask_in ), with the genuine param order; keep polling only as a fallback.
10. **(c) headers** -- add `Connection: Keep-Alive`; send Content-Type BEFORE User-Agent and
    Content-Length LAST; GET carries no Content-Type/Content-Length (already true).
11. **(e) event** -- after the (non-organic) attribution answer, POST /event with event_token y3sjx5,
    callback_params {"google_adid": gaid}, partner_params, seq=1, event_count=1,
    session_length/time_spent ~= seconds since the session.
12. **(b/c) click chain** -- click with a mobile-browser UA and NO Client-SDK header; check with the
    network why `{loop_id}` is passed through unsubstituted in ip_address= (or strip the param);
    prefer the genuine-shaped go.link click (payrupik.go.link, tracker 248wk8ym) over
    app.adjust.com/2015o4dz if the team can get that link.
13. **(b) device/geo story** -- our profile says country=IN + mcc 405 / mnc 872 + tz +0000; the genuine
    hanafintech device says country=AE, tz +0530.  Align the device profile with the IP geo that
    actually performs the click+install (and the offer's target geo).

## 8. Raw extracts (reproducible)

* genuine request headers/values resolved from the chls ArrayList pairs; handle map: ok (10 strings, positions monotonic vs handles)
* genuine bodies span-verified against each request's Content-Length header (1280/1576/1270)
* our four signed requests parsed from run_hanaf.log verbatim
