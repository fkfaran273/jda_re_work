# Offline crosscheck — is the Python-booked 1e63c600 record really Organic, or is the minted blob only masking it on read?

**Date:** 2026-09-27
**Device:** moto g42 (ZD2228MY3X, Android 12, root via `/debug_ramdisk/su`)
**Identity under test:** gps `1e63c600-e86b-4e92-a6c3-63846dd6057c` · adid `6a8f535a13e23278c67aece378105c25` · installed_at `2026-09-27T15:56:03Z` (the record offline_test2 booked at 15:55–15:56Z)
**App:** com.penti.app · token `jut9tib0eeps` · client_sdk `android5.7.0`

## The question

`offline_test2` (Python click → Python-minted blob → Python session → Python read) ended **Organic**. But `transport_test.md` proved `/attribution` **verifies** the Authorization blob — a bad blob gets an Organic *fallback* even on a genuinely non-organic record. So the offline Organic could be either (a) the record really is Organic, or (b) the record is non-organic and the minted blob failed the read.

This crosscheck removes the minted blob from the read path entirely: the **device itself** (the app signing with its own genuine TEE signature) reads the record, and the app's genuine blob is then replayed from Python.

## What was done

1. **Pinned the identity onto the device.** `/data/data/com.google.android.gms/shared_prefs/adid_settings.xml` pulled binary-safe (`exec-out su -c "base64 …"`), old GAID `37e70820-dabc-4d5e-a34d-eff8b27f01f7` byte-replaced by `1e63c600-e86b-4e92-a6c3-63846dd6057c` (same 36-byte length, 608 B file), pushed (`MSYS_NO_PATHCONV=1 adb push` → `su cp` into place, owner `u0_a207`, mode 660), `am force-stop com.google.android.gms`. Original XML backed up at `/data/local/tmp/adid_settings.xml.bak`.
2. **Wiped app data.** `am force-stop com.penti.app` + `rm -rf files shared_prefs databases` (the previous stored attribution on the device was Organic `wy7261z`, installed 13:54:47Z — a different, older record).
3. **Launched com.penti.app** (monkey) and polled `/data/data/com.penti.app/files/AdjustAttribution` every 5 s for up to 180 s. The app signs its own `/attribution` with a **genuine** blob (the LSPosed adj9 oracle was live: 6 fresh `type=authorization_header` blocks, ts 16:13:47–16:13:51Z, 256-byte blobs).
4. **Genuine-blob replay.** Pulled the fresh capture log, extracted all 6 genuine blobs, and replayed GET `/attribution` for gps `1e63c600` from Python (`http.client`, the app's fresh auid `f2089155-1916-4052-8a95-1370799ec241`) using the app's own blob.
5. **Endpoint discrimination control** (same day, same endpoint): the transport-test oracle identity `2db6422f-…` (genuinely `24xg6t54`) with its genuine blob → and with byte0-bit0 flipped.

## Results

### 1. Device oracle (app's own genuine signature) — **ORGANIC**

AdjustAttribution, found 5 s after launch:

```
{"tracker_token":"wy7261z","tracker_name":"Organic","network":"Organic",
 "engagement_time":"0001-01-01T00:00:00Z","installed_at":"2026-09-27T15:56:03Z",
 "first_session_time":"2026-09-27T15:56:03Z","is_reattributed":false,
 "is_redownload_install":false}
```

Identity continuity is proven, not assumed:
- `installed_at 15:56:03Z` = exactly the `installed_at` offline_test2 planted in its session params (click+35 s) — this is the Python-booked record, not a fresh device record.
- The server assigned the app **the same adid** `6a8f535a13e23278c67aece378105c25` that the Python session received.
- The app's fresh `AdjustIoActivityState` holds auid `f2089155-…`, and the query went out with the pinned gps `1e63c600`.

### 2. Genuine-blob read from Python — **ORGANIC** (agrees)

Two of the app's fresh blobs (last and first of the burst) replayed via Python:

```
blob 0 (ts 1790525631415)  HTTP 200  wy7261z / Organic  installed_at 15:56:03Z
blob 1 (ts 1790525627411)  HTTP 200  wy7261z / Organic  installed_at 15:56:03Z
```

### 3. Endpoint control — the endpoint still verifies today

| arm | blob | verdict |
|---|---|---|
| GENUINE-ORACLE (2db6422f, genuine) | genuine | **24xg6t54 / VKM Digital Yeni** |
| FLIP-ORACLE (byte0 bit0 flipped) | corrupted | **wy7261z / Organic** |

So a genuine blob still reads a non-organic record as non-organic on this endpoint *right now*. The two Organic verdicts above are true reads, not Organic-fallback from a rejected signature.

## Verdict

| leg | result |
|---|---|
| Device oracle (app's genuine signature, own identity) | **Organic (wy7261z)** |
| Python read with the app's genuine blob | **Organic (wy7261z)** |
| Endpoint control (oracle identity) | genuine → `24xg6t54`; flipped → Organic |

**The gps `1e63c600` record is genuinely Organic. The minted blob is NOT the read-blocker — the offline Organic read was the true state of the record. Booking genuinely fails.**

## Conclusion and where the gap is

- The offline funnel's read leg is exonerated: a correct (device-genuine, and server-verified) signature reads the same Organic. Had the record been non-organic, both the device and the genuine-blob replay would have returned `24pxw9rl / VKM Digital Yeni`.
- The gap is in the **write path**: offline_test2's click (302, referrer `adjust_reftag=cHHZn3KuKm5K6&utm_source=VKM+Digital+Yeni&utm_campaign=AH…`) and `/sdk_click` both got clean HTTP 200s — but `/sdk_click` behaves like `/session`: a 200 ACK is **not** signature-gated and does **not** mean the referrer was credited. The server accepted the request and still left the record Organic, i.e. the referrer/attribution linkage never landed on the record. (Whether the server ignores the referrer because the minted blob fails *inside* the sdk_click processing, or for click-matching reasons — reftag freshness, IP/UA binding between click and sdk_click — is the next experiment; this one only proves the failure is real and not a read artifact.)
- offline_test2's own bottom line ("the gap remains in the booking session") is confirmed by an independent oracle.

## Artifacts

- `crosscheck_run.py` / `crosscheck_device_result.json` — pin, wipe, launch, poll, verdict
- `crosscheck_capture.log` (fresh capture log pulled from the device), `crosscheck_extract_blobs.py`, `crosscheck_ids.json` — 6 genuine blobs + fresh device ids
- `crosscheck_genuine_read.py` / `crosscheck_genuine_read_result.json` — genuine-blob Python reads
- `crosscheck_control.py` / `crosscheck_control_result.json` — endpoint discrimination control
- `crosscheck_device.py` — base64-wrapped su helpers (MSYS mangling of compound adb shell commands was the cause of the initial "Permission denied" noise; all device access goes through it)
- Device leftovers: GAID still pinned to `1e63c600…`; original XML at `/data/local/tmp/adid_settings.xml.bak` (GAID `37e70820…`)
