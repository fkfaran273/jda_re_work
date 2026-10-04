# Transport fingerprint test — does the HTTP transport decide signature recognition?

**Date:** 2026-09-27
**Target:** `app.adjust.com` · app `com.penti.app` · token `jut9tib0eeps` · adj9 signing
**Device:** moto g42 (ZD2228MY3X, Android 12, BoringSSL) — the transport-D control
**Scripts:** `transport_fingerprint_test.py` (battery), `transport_control_test.py`
(controls), `transport_attr_matrix.py` (the oracle matrix)

## ANSWER

**Every transport passes. Transport is not the discriminator.**
A, B, B2, B3, C, C2 and D all returned the *identical* recognized attribution
(`tracker_token=24xg6t54`), while all four negative controls fell back to
Organic. `app.adjust.com` verifies the adj9 blob as a **header payload**, not as
a TLS/HTTP fingerprint — so the JA3, cipher order, ALPN, HTTP header order and
egress IP are all irrelevant to recognition.

No Fiddler capture was needed. (Nothing is listening on 127.0.0.1:8888 anyway.)

## The oracle (this is the part that was previously missing)

Recognition can only be *read* on an identity that genuinely has a non-Organic
attribution. Two identities were available and only one works:

| identity | server truth | usable as oracle? |
|---|---|---|
| `363e5b78-…604111b` (task-pinned) | **genuinely Organic** | **No.** Every arm correctly returns Organic, so the endpoint *looks* signature-blind. This is what made earlier runs read as "all transports fail". |
| `2db6422f-…70beec9` (capture row 4, 09-24) | `24xg6t54` / VKM Digital Yeni | **Yes.** Correct signature → campaign; anything else → Organic. |

A genuine (non-Organic) attribution on the oracle identity:

```
tracker_token    24xg6t54
tracker_name     VKM Digital Yeni::AH::vkm_0926_36::cline_1p8t3
network          VKM Digital Yeni
engagement_time  2026-09-24T17:03:18Z
```

## Result table — GET /attribution, oracle identity, genuine blob

All arms: identical 549-byte query, identical Authorization header, identical
header set, same PC, back-to-back (this endpoint is ungated). Only the
transport varies.

| arm | transport | HTTP | verdict | tracker_token | engagement_time |
|---|---|---|---|---|---|
| A | python `http.client` (CPython/OpenSSL) | 200 | **PASS (RECOGNIZED)** | 24xg6t54 | 2026-09-24T17:03:18 |
| B | curl_cffi `chrome131` | 200 | **PASS (RECOGNIZED)** | 24xg6t54 | 2026-09-24T17:03:18 |
| B2 | curl_cffi `chrome124` | 200 | **PASS (RECOGNIZED)** | 24xg6t54 | 2026-09-24T17:03:18 |
| B3 | curl_cffi `chrome119` | 200 | **PASS (RECOGNIZED)** | 24xg6t54 | 2026-09-24T17:03:18 |
| C | tls_client `okhttp4_android_11` | 200 | **PASS (RECOGNIZED)** | 24xg6t54 | 2026-09-24T17:03:18 |
| C2 | tls_client `chrome_120` | 200 | **PASS (RECOGNIZED)** | 24xg6t54 | 2026-09-24T17:03:18 |
| D | **device curl** (BoringSSL, phone IP) | 200 | **PASS (RECOGNIZED)** | 24xg6t54 | 2026-09-24T17:03:18 |

Negative controls (must fail):

| control | HTTP | verdict | tracker_token |
|---|---|---|---|
| FLIP — blob byte0 bit0 flipped, stdlib | 200 | FAIL (Organic) | wy7261z |
| FLIP-D — blob byte0 bit0 flipped, device curl | 200 | FAIL (Organic) | wy7261z |
| NOAUTH — no Authorization, stdlib | 200 | FAIL (Organic) | wy7261z |
| NOAUTH-D — no Authorization, device curl | 200 | FAIL (Organic) | wy7261z |

All 7 genuine arms agree on one `tracker_token` → the response is
**transport-independent**. All 4 controls fall back to Organic → the blob
**is** being verified, so the test has real discriminating power.

## TLS fingerprints (the lead this rules out)

Sniffed ClientHellos, from `transport/tls_fingerprints.json`:

| transport | TLS ver | ciphers | exts | ALPN | ja3 sha256[:16] |
|---|---|---|---|---|---|
| A http.client (OpenSSL) | 3.3 | 17 | 10 | *(none)* | `652233d7046eddda` |
| B curl_cffi chrome131_android | 3.3 | 16 | 17 | h2,http/1.1 | `e3dbcccc342e4352` |
| B2 curl_cffi chrome99_android | 3.3 | 16 | 17 | h2,http/1.1 | `cf9a2ed75312b7ba` |
| B3 curl_cffi chrome131 desktop | 3.3 | 16 | 17 | h2,http/1.1 | `baa802f01431b073` |
| C tls_client okhttp4_android_12 | 3.3 | 15 | 11 | h2,http/1.1 | `51d2c9c3a8eac731` |
| C2 tls_client okhttp4_android_13 | 3.3 | 15 | 11 | h2,http/1.1 | `9610b334222d359b` |
| D device curl (Android BoringSSL) | 3.3 | 18 | 10 | http/1.1 | `212ce3bee66e529c` |

Seven mutually incompatible fingerprints — including arm A which negotiates **no
ALPN at all** and arm D which is the phone's own BoringSSL with only `http/1.1`
— produce the same answer. Fingerprint is conclusively **not** the gate.

## Endpoint asymmetry: /attribution verifies, /session does not

This is the important secondary finding and it explains the earlier
"all transports fail" readings.

**`/attribution` — signature-gated.** Genuine blob → campaign; flipped blob or
no auth → Organic. Sharp, ungated, usable as an oracle.

**`/session` — NOT signature-gated.** A blob with byte0 bit0 flipped was
accepted with a clean `200 {"ask_in":5000,"adid":"9423ba56…"}`, and `adid` is
derived from `gps_adid`, not from signature verification. The 20-minute
"too frequent session" gate is likewise a pure timestamp check that the
**corrupted-blob and no-auth controls hit identically** — so a `400 too
frequent` reply is not evidence of anything signature-related.

`/session` POST battery (identity `7cc81be0-…f2634a`, which was **unbooked**):

| arm | transport | HTTP | verdict | key field |
|---|---|---|---|---|
| A | python http.client | 200 | RESP (clean, only ungated shot) | new adid `d3a205a1c77e219be02d5bbf2d814d51` |
| B | curl_cffi chrome131 | 400 | gate | gap=5s, min 20m |
| B2 | curl_cffi chrome124 | 400 | gate | gap=9s |
| B3 | curl_cffi chrome119 | 400 | gate | gap=14s |
| C | tls_client okhttp4_android_11 | 400 | gate | gap=19s |
| C2 | tls_client chrome_120 | 400 | gate | gap=23s |
| D | device curl | 400 | gate | gap=28s |
| FLIP | control (corrupted) | 400 | gate | gap=33s |
| NOAUTH | control (no auth) | 400 | gate | gap=38s |

Only one clean `/session` verdict is obtainable per identity per 20 minutes, so
`/session` cannot be used to compare transports. `/attribution` can, and it
says they are all equal.

## Fingerprint lead

**None — and that is the finding.** There is no transport/fingerprint lead to
chase. The remaining variable is purely the **blob + header contents**. Anything
reporting Organic on an identity that genuinely has an attribution is failing on
its signature (wrong `key2`/key material, wrong canonical param set, wrong
param ordering, or a stale/mismatched blob), not on its network stack.

## Notes / gotchas found

- The task's suggested attribution query
  `?gps_adid=<gps>&activity_kind=attribution&initiated_by=sdk` returns
  `404 {"error":"Attribution request failed (failed to get app token)","ask_in":2592000000}`
  for **every** transport including no-auth. It has no `app_token` key, so it is
  a param error, not a recognition read. The full 23-key app param set is
  required.
- `transport_session.json` holds a session for gps `7cc81be0-60a0-4342-a878-eb5ee4f2634a`,
  which is **not** the identity the task pins (`363e5b78-…`) and does not appear
  in `transport_capture_log.txt` (whose rows are `363e5b78` and `2db6422f`).
  `7cc81be0` was unbooked and was booked by this run.
- The device's toybox curl is 7.73.0 / BoringSSL. Its script is pushed with
  `MSYS_NO_PATHCONV=1 adb -s ZD2228MY3X push` and run via `sh` so the
  `Authorization` value cannot be mangled by host-side quoting.

## Artifacts

- `transport/fp_attr_full_results.json` — attribution battery, task-pinned identity
- `transport/fp_attr_3param_results.json` — 3-param control
- `transport/fp_session_results.json` — /session battery
- `transport/control_results.json` — flipped-blob / no-auth controls
- `transport/attr_matrix_results.json` — **the oracle matrix (decisive)**
- `transport/tls_fingerprints.json` — ClientHello fingerprints
