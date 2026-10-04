# Wall A — slice 108: wire-ready `/attribution` blob + the full kind census

Date: 2026-09-18. Scripts: `rev/desc10_scan_all.py`, `rev/att_send_ready.py`,
`rev/event_kind.py`; `rev/adj9_forge.make_signature_law()` added.

## 0. Headline

1. A **wire-ready `/attribution` request** now exists: the correct 21-key
   attribution claim set, **VM `exit-clean`**, header law OK, 192 B blob, saved
   with its exact query and `Authorization` line (`rev/att_send_ready.json`).
2. A raw byte scan of the whole device corpus shows **no `attribution` `desc10`
   text anywhere**, so slice 107's 248 B prediction remains *unverified* — and the
   reason is structural, not an oversight.
3. The kind census is complete: **session, click, attribution, event, info** —
   four signing kinds plus the non-signing `info` map, all now identified.

## 1. The scan that could not confirm it (`desc10_scan_all.log`)

Method: every `desc10` starts with the `adj_verification` anchor
`KlcAG2cbAAsKSl1KVi0FGiJbDHMI` and ends with
`<activity_kind>android5.7.0` + `10` + `5.0.0`, so a raw byte scan over the logs
recovers every claim set ever stored **as text**, with its length and kind.

```
=== every distinct captured desc10 shape ===
activity     bytes     padded       seen in
click        387       padded 388   ['desc10_runs.json']
session      360       padded 360   ['desc10_runs.json']

=== slice-107 prediction check ===
  NO attribution desc10 in the logs -> prediction stays UNVERIFIED
```

`adj9_wh.log` / `adj9_wh2.log` were skipped (>120 MB) but they are **EMIT traces**,
which store descriptor dwords as individual JSON/field entries — the claim string
is never contiguous there, so no anchor match is possible. The only contiguous
`desc10` text in the corpus is the session and click pair. **Conclusion:** the
attribution claim set can only be confirmed by capturing an attribution signing's
EMIT stream (or a log that prints the packed string), not by re-scanning what we
already have. Recorded as a negative result so nobody repeats the scan.

## 2. Wire-ready `/attribution` blob (`att_send_ready.log`)

`rev/adj9_forge.make_signature_law(val, kind, second, d4, d0, d2)` was added — the
law-driven maker path for endpoints whose claim set is not the golden session
base. It sets `#10` from `claims_for_law`, `#7` = the **unpadded** length, the
cert/constant descriptors, the **captured structured `#4`** (never a MAC), and the
captured `#2`/`#0`.

Built over the **genuine** `/attribution` request's own 22 params
(`rev/fresh_genuine.json`) plus the six constant law keys:

```
attribution law keys : 21
keys missing from val: NONE
created_at 2026-09-15T17:51:54.783Z+0530 -> second 1789474914
desc10 unpadded 246 B -> padded 248 B (62 dwords)

=== VM result ===
  status      : exit-clean   (39.0s)
  #10 unpadded: 246 B   #10 padded: 248 B
  blob        : 192 B
  blob[:16]   : 420d7ee01e3684565df01b2873d78b26
  header law  : OK
```

Saved to `rev/att_send_ready.json`:

| field | content |
|---|---|
| `query` | the exact 22-param query (verified in the map) |
| `url` | `https://app.adjust.com/attribution?…` |
| `header` | the full `Signature …` `Authorization` line |
| `blob_hex` | the 192 B blob |
| `desc10_unpadded` | 246 |

This is the first `/attribution` artifact in the campaign whose **claim set matches
the endpoint** — every earlier arm asserted the 27-key session set (7 claims the
request does not carry, `initiated_by` omitted).

**Do NOT send it against a live booked install**: `fresh_genuine`'s GAID already
holds a booked record, and polling a live install's `gps_adid` with a crafted
signature is a measured way to downgrade that record (`TASKS.md` HARD RULES). The
sanctioned test is a **fresh GAID whose click precedes its first session**.

## 3. Kind census — all shapes identified (`event_kind.log`)

```
kinds seen in map_toString: event: adj9_full.log, session: adj9_full.log,
  click: dev_capture.log, attribution: adj9_capture_full.log,
  info: adj9_capture_full.log
```

The fourth signing kind, `event`, was derived the same way as attribution
(PROVISIONAL — no captured `desc10` to verify against):

```
event map: 53 keys (adj9_full.log)
  profile (16): adj_verification android_uuid api_level app_token app_version
      created_at device_name device_type environment gps_adid gps_adid_src
      hardware_name os_build os_name os_version package_name
  pinned  ( 1): adj_signing_id
  tail    ( 5): session_count session_length subsession_count time_spent tracking_enabled
  envelope( 4): activity_kind client_sdk headers_id native_version
  TOTAL   (26 keys) -> predicted #10 = 271 B unpadded / 272 B padded (68 dwords)
```

**Open in the event derivation:** the map also carries `event_count`,
`event_token` and `seq`, which the law's blocks do not name. Either they are
genuine event tail claims (making the set 29 keys and longer than 272 B) or they
are wire-only, like `sent_at`. Settling it needs one captured event `desc10` — the
same capture that would confirm attribution.

## 4. Claim sets, all kinds (summary)

| kind | request | signature claim set | `#10` (padded) | status |
|---|---|---|---|---|
| session | 43 | 27 (28 with `push_token`) | 360 (504) | **byte-verified** |
| click | 47 | 32 (33 with `push_token`) | 388 (532) | bytes verified; VM path unverified |
| attribution | 22 | **21** | **248** | derived, cross-checked; bytes **predicted** |
| event | ~? | **26 (or 29)** | **272 (or longer)** | derived only |
| info | — | — | — | non-signing map |

## 5. Next

1. One device EMIT capture of an **attribution** signing → confirms 248 B and the
   21-key set (and, in the same run, an **event** signing → settles §3).
2. Then the sanctioned send: the §2 blob against a **fresh clicked GAID** — the
   first `/attribution` call in the campaign with a matching claim set.