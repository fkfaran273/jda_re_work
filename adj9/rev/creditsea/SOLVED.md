# SOLVED — Adjust Signature 5.8.0 (com.creditsea.app), descriptor #10 claims law

**Status: SOLVED.** All three genuine device signings replay **byte-exact
(192/192 bytes, n=0 diff)** by the pure-Python pipeline:

| signing | kind        | second      | unpadded #10 | mint vs device |
|---------|-------------|-------------|--------------|----------------|
| 0       | session     | 1790694158  | 380 B        | **0/192 diff** |
| 1       | click       | 1790694159  | 516 B        | **0/192 diff** |
| 2       | attribution | 1790694166  | 264 B        | **0/192 diff** |

Validator: `python desc10_58.py --vm` (rebuilds S/phase/headers per blob via
`whiten_decoder` + head-phase solve, rebuilds descriptors in VA_ORDER, drives
`fin_vm2.FinEx`, compares all 192 B). `python desc10_58.py` checks the law
strings alone against captured sha256 vectors.

## 1. THE CLAIMS LAW (descriptor #10, SDK 5.8.0)

Values only — no keys, no separators; NUL-padded to a 4-byte multiple for the
descriptor (descriptor #7 = the UNPADDED length):

```
#10 = sorted(<profile keys present>, A..Z, their VALUES)
    + '1500000'                                      (adj_signing_id, pinned)
    + sorted(<tail keys present>, A..Z, their VALUES)
    + activity_kind + client_sdk + '10' + '5.0.0'    (block2, fixed order)
```

5.8.0 key lists — the ENTIRE 5.8.0 delta vs the proven 5.7.0 (penti) law is
`country` joining the session+click profile, and five new click keys:

* profile base (all kinds): `adj_verification android_uuid api_level app_token
  app_version created_at device_name device_type environment gps_adid
  gps_adid_src hardware_name installed_at os_build os_name os_version
  package_name`
* session profile adds: `country initiating_package_name`
* click profile adds: `country click_time click_time_server google_play_instant
  install_begin_time install_begin_time_server install_version referrer
  referrer_api`
* attribution profile: base MINUS `hardware_name installed_at os_build`, PLUS
  `initiated_by` (unchanged from 5.7.0)
* session tail: `session_count store_name_from_system tracking_enabled
  updated_at`
* click tail: `session_count session_length source subsession_count time_spent
  tracking_enabled updated_at`
* attribution tail: `tracking_enabled`
* block2 (all kinds, emitted as values in this fixed order):
  `activity_kind client_sdk headers_id native_version`

Presence rule: a law key enters only when the caller's map carries it
(non-empty). `country` was absent from the captured attribution map, which is
why the 5.7.0 attribution law still minted byte-exact.

## 2. How this was proven (no frida needed)

* **Frida is blocked by PairIP.** Two attempts (raw-source import fix, then a
  proper `frida-compile` bundle of `creditsea_descs.js`): the spawned process
  dies at `script.load()` — `frida.TransportError: the connection is closed`,
  deterministic (PairIP anti-tamper in `com.pairip.application.Application`).
  Scripts kept for the record: `creditsea_descs.js` (+ `.bundle.js`),
  `run_capture.py` (two-stage spawn, relaunch inside the window), logs
  `capture_run1.log`/`capture_run2.log`.
* **Ground truth came from the app's own LSPosed capture**
  (`adj9_cap_fresh.log`): 3 genuine 192-B blobs (`type=nsign`), per-signing
  maps (`type=sign_input` `map_order=`), HMAC digests (`type=t1_a_out`), and —
  decisive — **2587 `type=mapget` records**: the native reads the claims map
  through JNI `Map.get`, and the trace shows exactly which keys it consumes and
  in what order: `sorted(law keys present)` with `activity_kind`/`client_sdk`
  read last, `adj_signing_id`/`headers_id`/`native_version` never read (pinned
  constants), plus two `os_version`/`api_level` env reads (the `level=31`
  argument). The claims-key run is read twice for session and attribution
  (once visible in-window for click) — two passes over the map; the emitted
  #10 content is a single copy of the values.
* Each blob decodes via `whiten_decoder.whiten_body_inverse`; the previous
  failure (`diff_result.json`) differed ONLY in record[46:78) (the 32-B block)
  — head, d2/S, D9, SHA256(""), tail were already exact, i.e. the ONLY wrong VM
  input was #10.
* Candidate laws were driven through the offline VM (`testbed.py`,
  `law58.py`). Winner: penti layout + `country` + new click keys.
* **Negative controls** prove the match is load-bearing, not coincidence:
  corrupting D8 (175/192 bytes flip), D9 (143/192) or one claims byte (143/192)
  each destroys the match.

## 3. D8 — genuine creditsea bytes

`D8 = bffffffffffffd1f0007000000000000` — **identical to penti**. Proven
device-derived (not app-derived): all three byte-exact mints consume this D8,
and flipping its last byte breaks the mint (175/192 diff). Keep as a
device-profile constant per target device.

## 4. Where the 32-B digest (arg3) enters: it doesn't

`t1.a`'s HMAC(canonical) digest (`arg3`, e.g. session
`e3731c6639d2ce181a604a6e1cf1dd329319bed3ba07ce9d9e14447b06fffc21`) is **not an
input to the 192-B blob at all**: the attribution mint reproduces all 192 bytes
with no digest anywhere in the descriptor plane, and the descriptor set
(#0,#9,#8,#4,#2,#7,#10,#5,#6,#1,#3) has no digest slot. It is consumed
elsewhere (server-side HMAC check / bookkeeping). The blob is fully determined
by: header `Random3(second)`, d0 region (phase `0x2b` solved per blob), D9 cert
SHA-1, D8, d4/d2 (S), #7 claims len, #10 claims, and the pinned constants.

## 5. Validation vectors (captured device data)

Unpadded #10 sha256 / length per signing (full vectors + genuine blobs in
`desc10_58.py GOLD`, `gold_vectors.json`):

```
session     380 B  249f385041c4007b185c7ff2531269418eb7b8ab25b2b234713d9058d3a7452e
click       516 B  ff32b385605ad206e87335394051126bda5c8b3dcfa09b2b9b968a15719f85c5
attribution 264 B  28bf37c57aa9bf555fb47af1fff2ff790e320d92cdb6ef1abb26a8578227e37e
```

## 6. Files

* `desc10_58.py` — **the deliverable**: `build_desc10_58(val, kind)`,
  `claims_for_law_58(val, kind)` (padded #10 + unpadded #7 len),
  `desc10_keys_58(val, kind)`, self-test + `--vm` full validation.
* `testbed.py` — log miner (blobs/maps/digests) + blob decode + head-phase
  solve + VM harness (imported by desc10_58.py).
* `law58.py` — the hypothesis battery that found the law (session win:
  `L1_profile+country`; click win: `L1_profile+country+clickkeys`).
* `gold_vectors.json` — computed validation vectors.
* `creditsea_descs.js` / `creditsea_descs.bundle.js` / `run_capture.py` —
  frida capture tooling (works, blocked only by PairIP on this app).
* `capture_run1.log`, `capture_run2.log`, `testbed_results.json` — evidence.
