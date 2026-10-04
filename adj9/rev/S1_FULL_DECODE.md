# S1 full decode — QMgRTT9...NBNBQ (2026-09-14)

Source: `golden_saz.json:s1` = `pentindroid_logs.saz` session 1, OnePlus DN2101 / Android 11 / api 30.
Status: **HTTP 200 OK — server-accepted**. Verified offline byte-exact.

## 0. Raw
- base64 (256 chars):
```
QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNaSqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ
```
- raw: 192 bytes = 16 B header + 176 B body → Base64(NO_WRAP) = signature field.
- raw hex (192 B):
```
40c8114d3f66c6da1f0f75727e1c44e6cd6362ac5bdd7471299a3df3c48c41a3ae59041f81852c37524ad10a9193b2f907a4ded69abe96d74a4a68fcb86fba81a5dba0e2a8e6af8bae6e29be3770f30d38edb1a91f63b84df28b98a5205efef98b0ad8de4c4d4c1ee8f77bc4c3dc02ed83e9b83e5f7c48c875b0ec4b99e89d44384104578e1c97455004b3cc25c3035a4aa88a54b0bf9518849b995f47cf2bdb0311b0b295679b2ddbaed341f40228c634ba79caeee525f6bd90bcc78d04d050
```

## 1. Header (16 B) — DECRYPTED, clock only
- header hex: `40c8114d3f66c6da1f0f75727e1c44e6`
- dwords BE:
```
[0] 0x40c8114d
[1] 0x3f66c6da
[2] 0x1f0f7572
[3] 0x7e1c44e6
```
- MSB law 4/4: bytes 0/4/8/12 = 0x40,0x3f,0x1f,0x7e — all < 0x80 (31-bit draws).
- generator `header_gen.py::make_header(sec)` = srand(time) + bionic Random3 (TYPE_3, 31-word) → 8 draws → 4 XOR pairs → BE:
```
draws 1-8: 0x5bca8673, 0x1b02973e, 0x4a904f1a, 0x75f689c0, 0x27b28ae3, 0x38bdff91, 0x518af75c, 0x2f96b3ba
d0 = d1^d2 = 0x40c8114d ... (matches)
```
- second: **1788856523** → `2026-09-08T08:35:23Z` = `14:05:23+0530` = `created_at 14:05:22.928 + 1s` (header law).
- Same header as S2 (different endpoint, same second) → payload-independent proof.
- Verify: `python header_gen.py 1788856523` → same hex.

## 2. Authorization (6 fields, fixed order)
```
Signature signature="<above>",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
```
Order: signature, adj_signing_id, algorithm, headers_id, native_version, adj_verification (algorithm before headers_id).

## 3. adj_verification — DECRYPTED
- b64 `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` → 19-byte XOR key `Quoh8uafohgh7CahM2h` (s2.a, i%19) → UTF-8:
```
{"os_name":"android"}
```
Constant on Android. Inside HMAC input, not a signature.

## 4. Body (176 B = 44 dwords BE) — whitened record
BE dword stream (index 4..47 of full 48-dword blob):
```
 4 0xcd6362ac   15 0xb86fba81   26 0xe8f77bc4   37 0xb0bf9518
 5 0x5bdd7471   16 0xa5dba0e2   27 0xc3dc02ed   38 0x849b995f
 6 0x299a3df3   17 0xa8e6af8b   28 0x83e9b83e   39 0x47cf2bdb
 7 0xc48c41a3   18 0xae6e29be   29 0x5f7c48c8   40 0x0311b0b2
 8 0xae59041f   19 0x3770f30d   30 0x75b0ec4b   41 0x95679b2d
 9 0x81852c37   20 0x38edb1a9   31 0x99e89d44   42 0xdbaed341
10 0x524ad10a   21 0x1f63b84d   32 0x38410457   43 0xf40228c6
11 0x9193b2f9   22 0xf28b98a5   33 0x8e1c9745   44 0x34ba79ca
12 0x07a4ded6   23 0x205efef9   34 0x5004b3cc   45 0xeee525f6
13 0x9abe96d7   24 0x8b0ad8de   35 0x25c3035a   46 0xbd90bcc7
14 0x4a4a68fc   25 0x4c4d4c1e   36 0x4aa88a54   47 0x8d04d050
```
- 0/44 stable corpus-wide needed without inputs (fully whitened — `mine_body.py` 0 small-ints/XOR-triples).
- Model (`WALL_A_SLICE_78.md`, `fin_result.md`): blob = output stream F0[0..48) BE — header [0..4) + body [4..48). Workhorse 0x12a860 pure copier; whitening = value-routed merge passes + 465 LENQ accumulators. Inputs = 147 dwords: request claims + H (TEE HMAC opaque tag) + cert-SHA1 `fad0f10d…74bd` + level 30 + ns stamps + second + 144-B #0 env telemetry.
- H never raw-contained (BE/LE 0 hits) → whitened, not stored. #0 nonce write-only; server does duplicate-detect + known-slot parse (slice 83).

## 5. Request claims (whitening inputs) — 45 params
`POST https://app.adjust.com/session` — all body params = inputs:
```
store_name_from_system=com.android.vending, gps_adid_attempt=1, api_level=30,
hardware_name=DN2101_11_A.20, app_version=3.12.1, app_token=jut9tib0eeps,
installed_at=2026-09-08T14:00:02.774Z+0530, created_at=2026-09-08T14:05:22.928Z+0530,
wait_total=0.0, device_type=phone, language=tr, gps_adid=1a89cb29-3590-418c-ae2b-122bbd93e38f,
foreground=1, connectivity_type=1, mcc=405, device_manufacturer=OnePlus, display_width=1080,
device_name=DN2101, needs_response_details=1, os_build=RP1A.200720.011,
updated_at=2026-09-08T14:00:02.774Z+0530, cpu_type=arm64-v8a, retry_count=0, screen_size=normal,
screen_format=long, last_error=0, gps_adid_src=service, mnc=872, wait_time=0.0, os_version=11,
first_error=0, android_uuid=117d0470-c64e-4530-af62-48049861d40a, sent_at=2026-09-08T14:05:22.942Z+0530,
offline_mode_enabled=0, environment=production, screen_density=high, attribution_deeplink=1,
session_count=1, display_height=2293, package_name=com.penti.app,
initiating_package_name=com.android.vending, os_name=android, ui_mode=1, enqueue_size=0, tracking_enabled=1
```
Full JSON: `golden_saz.json:s1`. Extract any .saz with `python saz_session_log.py <path>`.

## 6. What "decrypt" means here
- Header: always invertible → second (done above).
- Body: decodes only with its request's claims — given here, fully verifiable offline via `fin_vm2.py FinEx` (48/48) and `trace_replay.py` (44/44). Without claims, only shape/MSB/header-law check possible.
- Making: `make_fresh.py + submit_fresh.py` → HTTP 200 with adid (H replayed, #0 zero/random accepted). No TEE key needed.

## 7. Re-verify
```
python header_gen.py 1788856523
python saz_session_log.py pentindroid_logs.saz
python fin_mapcmp.py 20000000 22272
python verify_saz_like_server.py  # 114/114
```
