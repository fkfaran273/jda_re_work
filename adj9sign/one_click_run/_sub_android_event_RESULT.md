# ANDROID adj9 /event claims law — DERIVED AND PROVEN (27/27 byte-exact)

Date: 2026-10-01.  Support task for the iOS /event effort; closes the gap
noted in `adj9/rev/TIMEZONE_AND_AUTHZ_RESULT.md` ("45 `event`/`info` signings
that our desc10 law does not implement").

## 0. TL;DR

The Android adj9 `/event` claims law is the **session law + 4 event keys**:

```python
EVENT_PROFILE_EXTRA = ['event_count', 'event_token', 'partner_params']  # sorted into PROFILE
EVENT_TAIL_EXTRA    = ['seq']                                           # sorted into SESSION_TAIL
# kind == 'event':
#   profile, tail = PROFILE + EVENT_PROFILE_EXTRA, SESSION_TAIL + EVENT_TAIL_EXTRA
```

Emission order (desc10_keys semantics unchanged): sorted profile keys present
→ PINNED `adj_signing_id` ("1500000") → sorted tail keys present → BLOCK2
(`activity_kind, client_sdk, headers_id, native_version`).  Serialization is
identical to session/click/attribution: bare latin-1 **values concatenated**,
presence-filtered, no separators, no escaping (`partner_params` JSON passes
through raw).

**Proof: 27/27 genuine on-device event signings mint byte-exact through the
signer's own `sign_pure` path** (with only the two list extensions above,
applied in memory — `adj9_signer.py` untouched), plus 27/27 block-hash
matches and 27/27 digest/header verifications.  Negative controls all fail
as required.

## 1. Capture hunt (task 1) — what exists on disk

### 1a. Network captures: NO adj9 /event request exists anywhere

Scanned every `*.saz`, `*.har`, `*.chls` under `C:/Users/Apps/Downloads/`
(recursive into `com.penti.app/`), plus `D:/Downloads - Copy/`:
`_sub_event_hunt.py` → `_sub_event_hunt_out.json`.

- 81 `/event` requests with a `signature="` Authorization header found in
  total; **26 are iOS** (`cainiaot1iosmodd_*.saz`, `consent.adjust.*`,
  `client-sdk: ios5.8.0` — the iOS agent's territory).
- **55 Android `/event` requests, none adj9:**

  | capture | client_sdk | algorithm | blob |
  |---|---|---|---|
  | avitoauto_3Sep_*.saz + avito_http.har (3) | android5.0.0 | legacy uppercase-hex | n/a |
  | doodhvaleauto_* (29) | flutter5.5.0@android5.5.0 | legacy uppercase-hex | n/a |
  | feonlineauto_repeat_lvl2_7sep_nokia.saz (18) | flutter5.4.3@android5.4.4 | legacy uppercase-hex | n/a |
  | m4marry_* (8) | android5.6.1 | **adj8**, `adj_signing_id="1400000"`, `headers_id="9"`, `native_version="3.67.0"` | 176 B |

- The genuine penti / creditsea SAZs
  (`penti_android_test.saz`, `pentindroid_logs.saz`, `pentindroid_update_8sep.saz`,
  `creditsea_newapp_ct*.saz`, `fiddler/pentindroid_logs.saz`) contain
  **only** `session`, `sdk_click`, `sdk_info` — zero `/event`.
- Charles `.chls` binary greps agree (avito: 6 raw `/event` + legacy sigs;
  all others 0).

### 1b. The real source: on-device frida traces (penti, android5.7.0)

`C:/Users/Apps/Downloads/com.penti.app/adj9/device/` contains full
signing-instrumentation captures (`###ADJ9_BEGIN/END` records): per signing a
192-B `nsign` blob, the complete claims map (`sign_input`/`map_order`), the
`authorization_header`, and every `Map.get` the native makes (`mapget`, in
call order).  Event-bearing files:

| file | signings | event signings |
|---|---|---|
| adj9_wh.log | 191 | 28 |
| adj9_wh2.log | 193 | 28 |
| adj9_mapget.mlog | 43 | 4 |
| adj9_ns.mlog | 50 | 14 |
| tail5.mlog | 4 | 4 |

After dedup by blob: **193 distinct signings — 77 session, 71 click,
18 info, 27 event**.  The 27 events are genuine app-generated event traffic
(event tokens `p90b20`×12, `29ah7d`×10, `ns5po2`×4, `axgfg1`×1; spread over
two capture days, ts 1789100655…1789213180), all penti
(`client_sdk=android5.7.0`, `d9 = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd`).

## 2. Derivation (tasks 2–3)

Per signing (`_sub_event_law_parse.py` → `_sub_event_signings.json`,
`_sub_event_law_prove.py` → `_sub_event_stage3.json`):

1. **Unseal**: `whiten_inverse(blob[16:160], blob[:16])` (from
   `_sub_unseal_core.py`) → 144-B record; all 27 pass every
   `record_constant_checks` layout law, and `predict_digest` matches
   blob[160:192] on 27/27 (same for the 148 known-kind signings).
2. **Fields read straight off the record**: `S = record[20:24]` big-endian
   (the d2 field — no seed brute-force needed), `head16 = record[3:19]`,
   `d9 = record[25:45]`, `block = record[46:78]`.
3. **Signing second**: scan `t` in `nsign_ts//1000 ± 120`,
   `make_header(t) == blob[:16]` → found 27/27, always within 2 s of the
   trace timestamp (header generated 0–2 s before the hook logged).
4. **Claims oracle**: the block hash
   `sha256_iv2(d9 ‖ 00 08 ‖ head16 ‖ LE32(S) ‖ sha256("") ‖ 01 00*16 ‖ claims)
   == record[46:78]` is a cryptographic commitment to the exact claims bytes,
   so candidate orderings were tested against it.
5. **Calibration**: the same mapget traces show the native reading claim keys
   in one alphabetical run per signing; for the 148 session/click/attribution
   signings the known law reproduces the block hash 148/148, and a full
   192-B mint (record rebuilt with the captured head16) is byte-exact
   148/148 — the verification machinery is sound before touching `/event`.
6. **Candidate search** over event-key membership/positions hit exactly one
   law (see §3).  The mapget order independently corroborates it:
   `…, package_name, partner_params, push_token, seq, session_count, …,
   tracking_enabled, activity_kind, client_sdk` — the 3 event extras read at
   their alphabetical profile slots, `seq` at the tail boundary, BLOCK2 last,
   and **no `adj_signing_id` map-get at all** (pinned id is emitted from a
   constant, exactly as in the session/click laws).

## 3. THE LAW (exact)

Presence-filtered (a key enters only when the map carries it non-empty):

```
sorted(PROFILE + ['event_count', 'event_token', 'partner_params'] present)
→ 'adj_signing_id'                       # PINNED, value "1500000"
→ sorted(SESSION_TAIL + ['seq'] present)
→ ['activity_kind', 'client_sdk', 'headers_id', 'native_version']   # BLOCK2, fixed order
claims = ''.join(values).encode('latin1')                            # unchanged
```

Full emission order for a penti event with every observed key present
(30 claims, matches `STATUS.md` "EVENT 30 named claims"):

```
adj_verification, android_uuid, api_level, app_token, app_version, created_at,
device_name, device_type, environment, event_count, event_token, gps_adid,
gps_adid_src, hardware_name, os_build, os_name, os_version, package_name,
partner_params, push_token,
adj_signing_id,
seq, session_count, session_length, subsession_count, time_spent,
tracking_enabled,
activity_kind, client_sdk, headers_id, native_version
```

Where each event-specific key sits:

| key | section | notes |
|---|---|---|
| `event_count` | PROFILE | alphabetical slot between `environment` and `gps_adid` |
| `event_token` | PROFILE | right after `event_count` |
| `partner_params` | PROFILE | between `package_name` and `push_token`; raw JSON value, unescaped |
| `seq` | TAIL, first | **after** the PINNED `adj_signing_id`, before `session_count` |

Definitive placements (block-hash arbitrated, strings differ):
- `event_count`/`event_token`/`partner_params` **before** the pinned id
  (putting them in the tail changes the bytes → hash fails);
- `seq` **after** the pinned id (seq-in-profile tested → hash fails);
- pinned `adj_signing_id` present in event claims, same "after profile"
  position as session (alphabetical-position variant → hash fails).

Not claimed despite being read/present in event maps: `seq`-adjacent request
fields and the whole request-only vocabulary (`algorithm`,
`attribution_deeplink`, `connectivity_type`, `cpu_type`,
`device_manufacturer`, `display_height/width`, `enqueue_size`, `first_error`,
`foreground`, `gps_adid_attempt`, `language`, `last_error`,
`needs_response_details`, `offline_mode_enabled`, `retry_count`,
`screen_density/format/size`, `sent_at`, `ui_mode`, `wait_time`,
`wait_total`, `android_id`/`fire_adid` — the latter two always null).
The native **reads** `seq` (between `push_token` and `session_count`) but the
hash proves it is emitted in the tail — read order ≠ emission position for
the boundary key.

## 4. Proof (task 4) — byte-exact mints

Verification run (`PROFILE += 3 extras`, `SESSION_TAIL += ['seq']`, in-memory;
`kind='session'` path of the unmodified signer):

```
event signings:                       27
record layout constants:          27/27
digest (double-padded MAC):       27/27
block-hash == claims commitment:  27/27
signing second recovered:         27/27
FULL 192-BYTE MINT (sign_pure):   27/27   ← byte-exact on every event signing
```

Calibration on the same traces: session/click/attribution full mints 148/148.

Worked example (`ts=1789100655061`, token `p90b20`):
`second=1789100654, S=2058507220, head phase=(), d9=fad0f10d…74bd,
claims_len=817` → `sign_pure` output == captured blob, byte for byte.
Head phases observed across the 27: `()` ×24, `(46,)` ×1, `(34,46)` ×2
(consistent with the documented free-selector property).

Negative controls (all fail, as they must):
- plain session law (no event keys) on event maps: 0/27 block matches;
- `seq` placed in PROFILE: 0/27;
- `event_*` keys placed in the tail: 0/27.

## 5. S / second recovery method that worked

- **S**: no brute force — unseal the blob (whiten_inverse, CBC-chained SPN
  inverse) and read `record[20:24]` big-endian (d2).  Verified by the full
  mints on all 175 signings.
- **second**: `make_header(t) == blob[:16]` scan over
  `[nsign_trace_ts/1000 − 120, +120]`; always found within 2 s.  (The trace
  ts is the hook's log time; the header was minted 0–2 s earlier.)
- For minting via `sign_pure`, the d0 selector phase must be recovered per
  signing (brute force over 0/1/2-length phases against `record[3:19]`);
  the phase is a free value per the signer docs.

## 6. Suggested signer patch (NOT applied — no existing file modified)

```python
EVENT_PROFILE_EXTRA = ['event_count', 'event_token', 'partner_params']
EVENT_TAIL_EXTRA    = ['seq']
# desc10_keys: elif kind == 'event':
#     profile, tail = PROFILE + EVENT_PROFILE_EXTRA, SESSION_TAIL + EVENT_TAIL_EXTRA
```

Everything else (pinned id, BLOCK2, serialization, whiten/digest/header) is
already kind-generic in `adj9_signer.py`.

## 7. Artifacts (all new files, in this folder)

- `_sub_event_hunt.py` / `_sub_event_hunt_out.json` — network-capture hunt (saz/har/chls)
- `_sub_event_law_parse.py` / `_sub_event_signings.json` — ADJ9 trace parser, 193 signings
- `_sub_event_law_analyze.py` / `_sub_event_stage1.json` — unseal + known-law verification
- `_sub_event_law_calib.py` — mapget-order inspection
- `_sub_event_law_prove.py` / `_sub_event_stage3.json` — law search + proof (27/27)
- `_sub_android_event_RESULT.md` — this file
