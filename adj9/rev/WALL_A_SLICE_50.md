# Wall A - slice 50: fetch clusters - 3 readers, double-sweep (2026-09-11)

`fetch_cl.py` (kept? no - one-off; pattern recorded): per-signing fetch
events with ts, 67 events over 619 ms for the reference signing.

## Three readers (temporal clusters)

- +0-27 ms: android_id, app_version, environment, fire_adid, client_sdk
  (5: nulls-once pair + 3 quintet members - early/Java-side setup?).
- +173 ms: api_level, os_version (the other 2 quintet members).
- +611-619 ms: FULL 30-key sweep TWICE back-to-back (60 gets in 8 ms):
  pass order identical both times (alpha bulk + appended tail:
  activity_kind/client_sdk (u2 globals!) + time_spent/tracking/updated_at
  + source/subsess). The ×3 quintet = early + 2x sweep; nulls = once each
  (miss short-circuit); rest exactly 2x.

## Sweep-2 battery (clean second pass, 30 keys, 4 encodings)

hashBE/raw/kv-pairs: all move dispatch#1 (0x30f791c/0x9bcc9dca/0xab6e36c3)
but stall at 1375-1410, no gateway/header. Same ceiling as ~90 variants
before: first decision steerable, passes 2+ need live workspace.

## Net

Fetch program fully characterized (readers, passes, order, counts). #0
candidates from it are exhausted as a class (temporal/dedup/sweep halves
x hash/raw/lens/kv/crc/fnv/adler/canonical). The encoding is NOT any
tested transform of fetched claims - remaining possibilities narrow to:
(a) non-claim bytes dominate #0 (timestamps/env/binary telemetry),
(b) a transform outside the tested family, (c) #0 assembled elsewhere
(feeders, not the fetch path at all).
