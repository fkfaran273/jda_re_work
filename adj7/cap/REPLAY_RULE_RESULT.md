# REPLAY RULE RESULT -- adj7 attribution replay

Run: 2026-10-07 13:02:15   (this machine, the capture's own public IP)

Golden capture: `payrupik_new/payrupik_new__adjust.json` sid 44 (fresh genuine install, booked NON-ORGANIC tracker **248wk8ym** / **VL-Alliance** minutes earlier on this same IP).

## Probe results

| probe | auth | times | result |
|---|---|---|---|
| PRIMARY | ours, mint_adj7 verbatim (hdrs_id 7 / native 3.61.0) | fresh | HTTP 200 -- Organic (tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)) |
| PRIMARY-B | ours, capture-faithful tail (hdrs_id 8 / native 3.62.0) | fresh | HTTP 200 -- Organic (tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)) |
| CONTROL-A | GENUINE capture auth verbatim | fresh | HTTP 200 -- Organic (tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)) |
| CONTROL-B | ours, capture-faithful tail | STALE (capture) | HTTP 200 -- Organic (tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)) |
| CONTROL-C | none | fresh | HTTP 200 -- Organic (tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)) |

## Full transcript

```
==============================================================================
ADJ7 REPLAY RULE  --  fresh genuine capture payrupik_new, sid 44
target verdict: NON-ORGANIC (tracker 248wk8ym / network VL-Alliance)
==============================================================================
capture sid 44: https://app.adjust.com/attribution?initiated_by=backend&gps_adid_attempt=1&api_level=31&app_version= ...
  22 query params; keys in wire order:
    initiated_by, gps_adid_attempt, api_level, app_version, app_token, os_version, created_at, device_type, gps_adid, foreground, android_uuid, sent_at, offline_mode_enabled, device_name, environment, needs_response_details, attribution_deeplink, package_name, os_name, ui_mode, gps_adid_src, tracking_enabled
  push_token in query? NO (this capture)
  UA: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)

------------------------------------------------------------------------------
OFFLINE LAW CHECK -- genuine sid 44 signature
  blob len 304 B, tag ok: True
  record a (nonce lo8 u64le) = 12137478147332815070
  record b (H)               = 599E004527744E846725E9E43569BCAE08C6E522FDB5B1CAB54EF8071AED175B
  record c (cert40)          = C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF
  record c == CERT ASCII     : True
  record d (nonce hi4 hex)   = 85006809
  record e == sha256('') up  : True
  nonce12 = deb8d66011fc70a885006809
  capture created_at 2026-10-06T15:47:41.741Z+0530 (epoch 1791281861, offset 19800s)
  H over claims(block2, 211 B)  == record b : True
  H over claims(no block2, 188 B) == record b: False
  H over claims(+push_token)   == record b : False  (must be False)
  header second = 1791281861 (created_at second 1791281861, delta +0s)
  PROVEN: the signed map == the 22 decoded query params, claims fold in block2 (activity_kind=attribution + client_sdk=android5.6.0), no push_token.

------------------------------------------------------------------------------
OFFLINE OUR-MINT SELF-CHECK (fresh times, signing second = now)
  fresh created_at = 2026-10-07T13:02:05.784Z+0530
  fresh sent_at    = 2026-10-07T13:02:05.797Z+0530
  mint: signing second 1791358325, blob 304 B, tag ok True, header ok True
  our record c == CERT ASCII : True
  our H recheck vs record b  : True
  our nonce12 = cd856a975d383c2a240c9bc7 (genuine deb8d66011fc70a885006809)
  record-vs-record (ours vs genuine):
    a: ours= 3043369422819067341 genuine=12137478147332815070 same=False
    b: ours=AFB6C8EE0E3FE0637AB2C003440D599CC8315779F6CD7871 genuine=599E004527744E846725E9E43569BCAE08C6E522FDB5B1CA same=False
    c: ours=C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF genuine=C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF same=True
    d: ours=240C9BC7 genuine=85006809 same=False
    e: ours=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934C genuine=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934C same=True
  diff claims (ours-fresh vs genuine-times): differ in the middle span (common prefix 64, suffix 133)
    A ...xi7gqwu39c3.0.42026-10-0 |7T13:02:05.784| Z+0530moto g42phoneprodu...
    B ...xi7gqwu39c3.0.42026-10-0 |6T15:47:41.741| Z+0530moto g42phoneprodu...
  diff raw query (fresh vs capture): differ in the middle span (common prefix 128, suffix 219)
    A ...=12&created_at=2026-10-0 |6T15%3A47%3A41.741Z%2B0530&device_type=phone&gps_adid=0a5863d0-66f6-4d15-b9ab-d388b77c8ba3&foreground=1&android_uuid=bd338228-9793-4b65-a4c6-2cc461e2801f&sent_at=2026-10-06T15%3A47%3A41.754| Z%2B0530&offline_mode_en...
    B ...=12&created_at=2026-10-0 |7T13%3A02%3A05.784Z%2B0530&device_type=phone&gps_adid=0a5863d0-66f6-4d15-b9ab-d388b77c8ba3&foreground=1&android_uuid=bd338228-9793-4b65-a4c6-2cc461e2801f&sent_at=2026-10-07T13%3A02%3A05.797| Z%2B0530&offline_mode_en...
  params whose raw value changed: ['created_at', 'sent_at']

==============================================================================
auth headers used:
  ours verbatim (mint_adj7): headers_id 7 / native 3.61.0
  ours faithful (rewritten): headers_id 8 / native 3.62.0
  genuine (capture)        : headers_id 8 / native 3.62.0

------------------------------------------------------------------------------
PROBE PRIMARY  our signature, fresh times, mint_adj7 verbatim auth
  auth: Signature signature="16F242EC6DCD958343E656E739C81AD11A67B1DE2AB47E0E8785346 ...
  HTTP 200
  body: {"app_token":"smxi7gqwu39c","adid":"6b575c41bbefc8caaccaf6faa01eac3a","attribution":{"tracker_token":"g0bpyt5","tracker_name":"Organic","network":"Organic","engagement_time":"0001-01-01T00:00:00Z","installed_at":"2026-10-06T10:17:39Z","first_session_time":"2026-10-06T10:17:39Z","is_reattributed":false,"is_redownload_install":false}}
  >> Organic  [tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)]
  >> RULE CHECK: FAIL

------------------------------------------------------------------------------
PROBE PRIMARY-B our signature, fresh times, capture-faithful auth tail (8/3.62.0)
  auth: Signature signature="16F242EC6DCD958343E656E739C81AD11A67B1DE2AB47E0E8785346 ...
  HTTP 200
  body: {"app_token":"smxi7gqwu39c","adid":"6b575c41bbefc8caaccaf6faa01eac3a","attribution":{"tracker_token":"g0bpyt5","tracker_name":"Organic","network":"Organic","engagement_time":"0001-01-01T00:00:00Z","installed_at":"2026-10-06T10:17:39Z","first_session_time":"2026-10-06T10:17:39Z","is_reattributed":false,"is_redownload_install":false}}
  >> Organic  [tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)]
  >> RULE CHECK: FAIL

------------------------------------------------------------------------------
PROBE CONTROL-A GENUINE signature verbatim, fresh times
  auth: Signature signature="29FC17E923F797F0074FC8914ED7FCBB70B21C2B0D58AE0EE64F7EA ...
  HTTP 200
  body: {"app_token":"smxi7gqwu39c","adid":"6b575c41bbefc8caaccaf6faa01eac3a","attribution":{"tracker_token":"g0bpyt5","tracker_name":"Organic","network":"Organic","engagement_time":"0001-01-01T00:00:00Z","installed_at":"2026-10-06T10:17:39Z","first_session_time":"2026-10-06T10:17:39Z","is_reattributed":false,"is_redownload_install":false}}
  >> Organic  [tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)]
  >> RULE CHECK: FAIL

------------------------------------------------------------------------------
PROBE CONTROL-B our signature (faithful tail), STALE capture times
  auth: Signature signature="16F242EC6DCD958343E656E739C81AD11A67B1DE2AB47E0E8785346 ...
  HTTP 200
  body: {"app_token":"smxi7gqwu39c","adid":"6b575c41bbefc8caaccaf6faa01eac3a","attribution":{"tracker_token":"g0bpyt5","tracker_name":"Organic","network":"Organic","engagement_time":"0001-01-01T00:00:00Z","installed_at":"2026-10-06T10:17:39Z","first_session_time":"2026-10-06T10:17:39Z","is_reattributed":false,"is_redownload_install":false}}
  >> Organic  [tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)]
  >> RULE CHECK: FAIL

------------------------------------------------------------------------------
PROBE CONTROL-C NO signature, fresh times
  auth: (none)
  HTTP 200
  body: {"app_token":"smxi7gqwu39c","adid":"6b575c41bbefc8caaccaf6faa01eac3a","attribution":{"tracker_token":"g0bpyt5","tracker_name":"Organic","network":"Organic","engagement_time":"0001-01-01T00:00:00Z","installed_at":"2026-10-06T10:17:39Z","first_session_time":"2026-10-06T10:17:39Z","is_reattributed":false,"is_redownload_install":false}}
  >> Organic  [tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)]
  >> RULE CHECK: FAIL

==============================================================================
SUMMARY
  PRIMARY   HTTP 200  Organic  tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)
  PRIMARY-B HTTP 200  Organic  tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)
  CONTROL-A HTTP 200  Organic  tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)
  CONTROL-B HTTP 200  Organic  tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)
  CONTROL-C HTTP 200  Organic  tracker=g0bpyt5 network=Organic adid=6b575c41bbefc8caaccaf6faa01eac3a (adid==capture: True)

RULE: our probes did NOT return NON-ORGANIC -- see the per-probe output and the offline diffs above.
```
