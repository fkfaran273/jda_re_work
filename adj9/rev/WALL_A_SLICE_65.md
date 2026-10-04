# Wall A - slice 65: endpoint-adaptive fetch sets (2026-09-11)

`thdiff.py` (kept? one-off; `thread_keys.json` kept): tail-5MB parse.

## Key sets by thread (values verified live)

- SdkClickHandler: 41 keys (1,148 gets).
- ActivityPackageSender: 36 keys (999 gets).
- adj9-oracle (probes): 36 keys.
- click-only (7): google_play_instant, referrer, referrer_api,
  session_length, source, subsession_count, time_spent.
- sender-only (2): initiating_package_name, store_name_from_system.
- common: 34.

## Meaning

The fetch program adapts to the endpoint map (click extras fetched only
for click signings). #0's composition therefore VARIES by endpoint type:
click-#0 (41-claim space) vs session/event-#0 (36-claim space). Tests must
be endpoint-matched (click content vs click blob, sender content vs
session blob) - cross-type content is structurally wrong by up to 7 keys.

## Next (falsifiable)

Endpoint-matched resim: click-fetch order (41, SdkClickHandler rows) vs a
click blob (same log, ts-paired nsign) and sender order (36) vs session
blob; metric = trajectory (dispatch/case/gateway/nrand) + body overlap
(header-excluded). A compositional match moves where cross-type never did.
