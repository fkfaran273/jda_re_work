# DIRECT_ADJUST_RUN.md — adj7 direct-adjust click cycle (adj9 click shape)

Date: 2026-10-07. One click, one install cycle. No retries.

## The click (direct, mobpine chain bypassed)

Script: `direct_click.py` (curl_cffi, impersonate=chrome131_android,
BROWSER_HEADERS from run_install.py, allow_redirects=False, manual Location hops,
empty gps_adid macros filled via the run_install `_fill_device_id` split-on-& rule).

Click URL used:

```
https://app.adjust.com/2015o4dz?campaign=HM2&adgroup=HM2_1722_&gps_adid=bb4262d6-89e3-4578-a945-602af857abe1
```

Hop trace:

```
HOP 0: HTTP 302  https://app.adjust.com/2015o4dz?campaign=HM2&adgroup=HM2_1722_&gps_adid=bb4262d6-89e3-4578-a945-602af857abe1
      adjust Date -> click_server_sec=1791392334
      -> Location: market://details?id=in.hanafintech&referrer=adjust_reftag%3DcgrDv6KgzmCQz%26utm_source%3DVL-Alliance%26utm_campaign%3DHM2%26utm_content%3DHM2_1722_
```

- gaid: `bb4262d6-89e3-4578-a945-602af857abe1`
- click_server_sec (adjust Date epoch): `1791392334`
- reftag (urldecoded, from the market:// hop's referrer= param — contains
  adjust_reftag= as required):

```
adjust_reftag=cgrDv6KgzmCQz&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_
```

Identical shape to the reftag the mobpine chain produced on the prior run.
Stored in `preclick2.env` (line 1 referrer, line 2 gaid, line 3 click_server_sec).

## The install

```
FUNNEL_ASK=sdk FUNNEL_GAID=bb4262d6-89e3-4578-a945-602af857abe1 \
FUNNEL_REFTAG="adjust_reftag=cgrDv6KgzmCQz&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_" \
FUNNEL_CLICK_SEC=1791392334 FUNNEL_CIT=30 python run_install.py > run_direct_adjust.log 2>&1
```

Exit code 0. Full log (`run_direct_adjust.log`):

```
campaign  in.hanafintech / smxi7gqwu39c (adj7, signing id 1300000, headers 8, native 3.62.0)
device    motorola moto g42 (Android 12, api 31)
signer    adj7_pure (pure Python, cert c1bfafcaffb8...)
[22:29:22] ==============================================================================
[22:29:22] ADJ7 INSTALL FUNNEL  app=in.hanafintech  gaid=bb4262d6-89e3-4578-a945-602af857abe1
[22:29:22] click: http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498&sub3=bb4262d6-89e3-4578-a945-602af857abe1
[22:29:22] ==============================================================================
click    reftag adjust_reftag=cgrDv6KgzmCQz&utm_source=VL-Alliance  [t=+0s]
[22:29:22] installing... (CTIT wall clock, 30s)
signing  /session ...  45 fields, blob 304 B  [t=+30s]
signing  /sdk_click ...  49 fields, blob 304 B  [t=+39s]
[22:30:05] session -> HTTP 200 adid 7905dc1957804d8d74efe866df715521
[22:30:05] sdk_click -> HTTP 200  {"app_token":"smxi7gqwu39c","adid":"7905dc1957804d8d74efe866df715521"}
attribution GET -> Organic / g0bpyt5  [t=+47s]
attribution re-ask +1.4s -> Organic / g0bpyt5  [t=+50s]
poll +3 s   -> Organic / g0bpyt5  [t=+55s]
poll +8 s   -> Organic / g0bpyt5  [t=+64s]
poll +20s   -> Organic / g0bpyt5  [t=+86s]
[22:30:48] FINAL ATTRIBUTION: {"tracker_token": "g0bpyt5", "tracker_name": "Organic", "network": "Organic", "engagement_time": "0001-01-01T00:00:00Z", "installed_at": "2026-10-07T17:00:01Z", "first_session_time": "2026-10-07T17:00:01Z", "is_reattributed": false, "is_redownload_install": false}
*** Organic / not joined ***   86s total
```

## FINAL VERDICT: **Organic / not joined**

| item | value |
|---|---|
| session | HTTP 200, adid `7905dc1957804d8d74efe866df715521` |
| sdk_click | HTTP 200, `{"app_token":"smxi7gqwu39c","adid":"7905dc1957804d8d74efe866df715521"}` |
| attribution ask 1 (t=+47s) | Organic / g0bpyt5 |
| attribution re-ask +1.4s | Organic / g0bpyt5 |
| poll +3s | Organic / g0bpyt5 |
| poll +8s | Organic / g0bpyt5 |
| poll +20s | Organic / g0bpyt5 |
| FINAL ATTRIBUTION JSON | `{"tracker_token": "g0bpyt5", "tracker_name": "Organic", "network": "Organic", "engagement_time": "0001-01-01T00:00:00Z", "installed_at": "2026-10-07T17:00:01Z", "first_session_time": "2026-10-07T17:00:01Z", "is_reattributed": false, "is_redownload_install": false}` |

## Notes

- No crash occurred, so the crash-safe re-poll path (last_run.json gaid/
  android_uuid, 3/8/20/30s gaps) was not exercised. `last_run.json` holds
  gaid `bb4262d6-89e3-4578-a945-602af857abe1`, android_uuid
  `a02b8733-898d-42a9-9c68-3e3dedea9a41`, adid
  `7905dc1957804d8d74efe866df715521`, click_second 1791392362.
- The click itself is a full success by the adj9 shape: adjust 302s directly
  to the market:// hop with a reftag in referrer=, gps_adid filled on the
  request, Date epoch captured. session + sdk_click both HTTP 200 with the
  adid returned. Adjust still attributes the install to Organic.
- Same outcome as the prior mobpine-chain run (also Organic, same reftag
  shape, same Organic tracker_token g0bpyt5). The direct-click construction
  removes the mobpine hop as a variable; the Organic verdict persists, so
  the join failure is downstream of the click construction (click-side
  device-id binding / attribution window on adjust's side remain the
  candidates), not in the redirect chain.
