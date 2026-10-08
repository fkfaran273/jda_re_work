# adj7 on iOS — native_variant 3.61.0 (CRACKED)

Cracked from `nirioiosauto_08Sep_ios_CT.saz` (app `com.fdjservices.nirio`,
iOS 16.4.6, iPhone10,1, Client-Sdk `react-native5.4.4@ios5.4.6`, 08 Sep
capture).  All 6 signed requests reproduce **byte-exact**:

    python adj7_ios_pure.py --selftest    # -> 6/6 BYTE-EXACT, SELFTEST OK

## TL;DR — the iOS law is the Android law with ONE crypto delta

| layer     | Android (`../adj7_pure.py`)             | iOS (this folder)                     |
|-----------|-----------------------------------------|---------------------------------------|
| header    | bionic rand(): 31-word LCG + Schrage fill, 310-draw warm-up, 8 draws, pair-XOR, big-endian | **raw MINSTD**: x = 16807·x mod 2³¹−1, seed = signing second, NO warm-up, same 8-draw pair-XOR big-endian packing |
| blob      | 304 B = header(16) ‖ body(256) ‖ tag(32) | identical                             |
| body      | CBC-AES-256, IV = header, key = SEED, measured ShiftRows SPN, no final SubBytes | identical (decrypt round-trips) |
| record    | `{ "a": <A> ,"b": "<H>","c": "<cert40>","d": "<D8>","e": "<sha0>" }\x00` + `0x10`×16 | identical layout |
| cert40    | NUL×40 (no-cert path)                   | **ASCII `"0"×40`** (0x30 bytes)       |
| H         | sha256 custom-IV0 over cert40 ‖ nonce12 ‖ sha0hex ‖ claims | identical (prefix = the ASCII zeros) |
| claims    | 98-key pool order, values bare, `1300000` pinned before `seq`, block2 (activity_kind, client_sdk) last | identical |
| tag       | HMAC-SHA256(DK37, blob[16:272])         | identical                             |
| auth hdr  | `Signature signature="…", adj_signing_id="1300000", algorithm="adj7", headers_id="…", native_version="…"` | same shape; **headers_id="7"**, native_version="**3.61.0**", signature hex UPPERCASE |

Constants (shared with Android): `SEED`, `DK37`, `IV0`, `ADJ_SIGNING_ID`
`1300000`.  Cracked iOS deltas: header PRNG = raw MINSTD, cert40 = ASCII
zeros, headers_id 7.

## Signing second

The header seed is the **unix second at signing (send moment)**, NOT
`created_at`'s second.  In the capture the six requests were created inside
the same second (…:09) but queued and signed 1–4 s apart — the brute force
matched each header at its own second (070/071/073).  Two requests signed in
the same second share the 16-B header (sids 32/33).

## activity_kind values seen

| endpoint              | activity_kind        |
|-----------------------|----------------------|
| `consent.adjust.com/session`              | `session`              |
| `consent.adjust.com/sdk_click`            | `click`                |
| `consent.adjust.com/attribution`          | `attribution`          |
| `consent.adjust.com/third_party_sharing`  | `third_party_sharing`  |

`client_sdk` = the `Client-Sdk` header value (`react-native5.4.4@ios5.4.6`),
appended as block2 with `activity_kind`, exactly the Android law.  Body
fields outside the 98-key pool (`enqueue_size`, `queue_size`, `retry_count`,
`foreground`, `offline_mode_enabled`, `send_in_background_enabled`,
`needs_response_details`, `attribution_deeplink`) contribute nothing — pool
filtering skips them, same as Android.

## Replay verification (`replay_attribution.py` — the major tool)

adj8 replay rules applied to iOS: replay the BOOKED capture's attribution
through OUR signature maker and compare the verdict with the logs.

- **offline**: same-to-same mint = **BYTE-EXACT** vs the captured 608-hex
  (sid 39, second 1788846076, nonce d6f5b597355eefc28fe6e520).
- **live same-to-same** (07 Oct 2026): request ACCEPTED — same adid
  `04b529e4...` resolves — but the capture's stale `created_at` (08 Sep)
  gets Adjust's throttle `ask_in: 3600000` (ask again in 1 h).
- **live --fresh** (fresh second + nonce + now-timestamps, claims re-signed):
  HTTP 200 + full attribution flow on the SAME adid.  Verdict today:
  `Organic` — the booked Kwanko click aged out of the attribution window,
  so the logged non-organic cannot re-assert a month later.
- **enforcement probe** (`--post session|third_party_sharing|sdk_click`,
  valid/none/broken triad): consent.adjust.com currently answers IDENTICALLY
  for broken and unsigned requests — the endpoint family does not
  hard-enforce the adj7 signature for this app today (device resolution by
  params).  The decisive signature proof is therefore the offline byte-exact
  mint (selftest 6/6); the live replay proves transport acceptance.

The same-to-same replay on a FRESH capture (replayed the day it is taken)
returns the logged verdict and is the end-to-end sign-off.

## The install funnel (`run_install_ios.py`)

    python run_install_ios.py --dry-run   # build + sign, send nothing -> "config is valid"
    python run_install_ios.py             # LIVE: click -> CTIT -> tps -> session -> attribution

Flow = the genuine iOS capture's request shapes (tps → session → GET
attribution, `initiated_by=backend` when ask_in returns) + the adj9
winning-flow lessons: fresh IDFA/IDFV per run, the click link carries that
SAME idfa (the iOS click→install join is the idfa match — there is no Play
referrer), CTIT via FUNNEL_CIT (default 22 s; adj9's wins were 7-8 s),
double-ask +30 s +60 s polls on Organic.

The click link defaults to the campaign link
(`https://app.adjust.com/1xgvk2dz?campaign=NIRIO_mobsuccess_iOS&adgroup=3710...")
with `{click_id}/{idfa}/{ip}/{creativeid}` filled per run; `FUNNEL_CLICK_URL`,
`FUNNEL_IDFA`, `FUNNEL_IP`, `FUNNEL_PROXY`, `FUNNEL_REFTAG`+`FUNNEL_CLICK_SEC`
override (same env interface as the Android `../run_install.py`).

**No sdk_click is fired on iOS**: the capture's sdk_click is `source=apple_ads`
with an AdServices attribution_token — faking it would contradict the tps+session
story; a direct tracker click joins the install by idfa, server-side.

### Signature-replay verification (`verify_replay.py`)

    python verify_replay.py   # -> 4/4 SERVER WOULD ACCEPT

Simulates the server's check on the funnel's own signed requests: DK37 tag,
SEED decrypt, record parse, **H recomputed from the received wire map** (the
replay binding), `1300000` pin in claims, ASCII-0 cert40, header =
MINSTD(second).  A signature that passes this is exactly what the server
recomputes on receipt — the 200/202 answer then only depends on the click
being registered for that idfa (the non-organic verdict, not the signature).

## Files

- `adj7_ios_pure.py` — the signer; imports the shared machinery from
  `../adj7_pure.py` and adds the iOS deltas.  `--selftest` mints all six
  capture signatures byte-exact and re-verifies tag + independent decrypt +
  record + H.
- `frozen_vectors.json` — the 6 capture vectors (params, kind, client_sdk,
  second, nonce12, sig) extracted by `freeze_vectors.py`.
- `replay_attribution.py` — the major verification tool (modes above).
- `probe_ios.py` — step 1: Android tag law + SEED decrypt on the iOS blobs.
- `probe2_claims.py` — step 2: claims-law match (6/6).
- `probe3_header.py` — step 3: PRNG-variant × second brute force → MINSTD.
- `run_install_ios.py` — the iOS install funnel (click + tps + session +
  attribution, adj9-flow lessons, all signed by `adj7_ios_pure`).
- `verify_replay.py` — server-side replay simulation over the funnel's own
  requests (tag/decrypt/H/pins) — 4/4 SERVER WOULD ACCEPT.
- `replay_capture_attribution.py` — THE user-rule test: the capture's sid-39
  attribution GET replayed verbatim with our signature making. Result in
  `REPLAY_RESULT.md` + `replay_result.json`: 2/2 HTTP 200, adid == capture —
  **signature layer accepted**; verdict re-answers Organic because the booking
  row is 29 days stale (the capture's own verbatim signature behaves the same;
  identical outcome to `../cap/replay_rule.py` on Android).
- `rearm_and_ask.py`, `rearm2_session_join.py` — oracle-row re-arm
  experiments (capture IDFA + fresh click, then signed session +
  attribution; v2 fires the capture's OWN 1zpd0epy go.link tracker).
- `replay_full_capture.py` — full capture-sequence replay (tps → session →
  attribution) with our sigs at the capture's own seconds.
- `fresh_noconsent.py` — the adj9_fresh_install PASS shape (idfa-less,
  att 0, tracking_enabled 0, fb_anon_id, curl_cffi) ported to nirio.
- `rearm_result.json`, `rearm2_result.json`, `fresh_noconsent_result.json`,
  `last_run_ios.json` — live-run artifacts.
- `freeze_vectors.py` — regenerates `frozen_vectors.json`.
- `nirio_08Sep/` — the extracted saz (JSON + raw hits).
- `nirioiosauto_08Sep_ios_CT.saz` — the original capture (copied in).

## Reproduce

    python probe_ios.py            # tag law 6/6 MATCH, records decrypt
    python probe2_claims.py        # claims law 6/6 MATCH
    python probe3_header.py        # [HIT] minstd_8xor on all 5 headers
    python adj7_ios_pure.py --selftest
