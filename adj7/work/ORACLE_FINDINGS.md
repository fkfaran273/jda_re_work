# ORACLE_FINDINGS.md — REAL Adjust signed map captured from in.hanafintech (device)

Date: 2026-10-06. Device: moto g42 (ZD2228MY3X), Android 12 (api 31),
app in.hanafintech v3.0.4, Adjust Signature SDK 3.62.0 (`native_version="3.62.0"`,
`algorithm="adj7"`, `headers_id="8"`, `adj_signing_id="1300000"`).
LSPosed module `com.adj9oracle` (retargeted) hooked the live SDK.

## 1. What was done (what worked, what didn't)

1. **Hook rewrite** — `adj9/module/src/com/adj9oracle/Hook.java` was replaced with a
   minimal oracle targeting only `in.hanafintech` (the old file hooked
   com.penti.app/creditsea/declic; the task note about a PKG4="xyz.be.customer" hook
   was stale — no such code existed). New hooks, tag **ADJ7ORACLE**:
   every `com.adjust.sdk.sig.Signer.sign` overload (before: dump each Map arg,
   every key=value in iteration order, chunked; after: same for all Map args incl.
   the filled output map), plus every `NativeLibHelper` method returning `byte[]`
   (= `nSign` and the `Z22222` wrapper) with the 304-B result blob as hex.
   NOTE: `Log.d` output did not survive in the main logcat ring buffer; the
   authoritative capture is the LSPosed daemon `modules.log` (XposedBridge.log
   writes the same lines, untruncated) — saved as `oracle_logcat.txt`.
2. **Build + install** — `bash adj9/module/build.sh` →
   `adj9/module/build/adj9-oracle.apk`, `adb install -r` OK.
3. **Scope** — `com.adj9oracle` was **disabled** and not scoped to the app. Fixed by
   editing the LSPosed config DB (pulled from `/data/adb/lspd/config/modules_config.db`,
   `UPDATE modules SET enabled=1, apk_path=<new> WHERE mid=59`,
   `INSERT scope (59,'in.hanafintech',0)`), pushed back during `stop`, then `start`.
   That soft restart killed LSPosed injection ("no response from bridge" — the lspd
   daemon survives `stop/start` but the zygisk bridge does not re-attach), so a
   **full reboot** was done; after reboot the module loaded into the app
   (`Loading legacy module com.adj9oracle ... hook ok: Signer.sign(Context,Map,Map,Map)`,
   `NativeLibHelper byte[] methods hooked=2`). Backup of the pre-edit DB:
   `/data/adb/lspd/config/modules_config.db.bak_hanaf` (on device).
4. **Triggering sign()** — first launches produced nothing: the app defers Adjust SDK
   init past onboarding (no app.adjust.com traffic at all until consent). Also, a
   relaunch within the session interval sends nothing. Working recipe:
   `pm clear in.hanafintech` → relaunch → tap through language screen → the first
   sign calls fired when the SDK initialized (Adjust event + session + sdk_click +
   attribution at 13:00:05–13:00:10). The app stayed on the phone-login screen the
   whole time — no OTP needed for these four calls.
5. **Parse** — `parse_oracle.py` → `hanaf_map.json` (one entry per sign() call:
   params map, globals map, output map, exact nSign merged map, blob hex).
   One parser fix mattered: chunk boundaries swallow the " | " separator (and
   logcat truncation of the long `arglens` lines), so maps are cross-checked
   against the sign()-entry dumps.
6. **Verify** — `verify_hanaf.py` (uses `adj7/adj7_pure.py` + `adj7/work/ks_inverse.py`):
   `record = cbc_dec(blob[16:272], blob[:16])`, parse a/b/c/d/e, recompute the
   commitment hash over claims built from the captured map.

## 2. The captured sign() calls

Four `Signer.sign(Context, Map params, Map globals, Map out)` calls, all on
`Adjust-pool-*` threads, each producing one 304-B blob via `nSign` (and an identical
blob via the `Z22222` wrapper — blobs byte-identical, `Z22222` wraps `nSign`):

| # | activity_kind | params keys | globals (3) | nSign merged map | blob |
|---|---|---|---|---|---|
| 1 | session      | 45 | endpoint, client_sdk, activity_kind | 51 keys | 304 B |
| 2 | click (sdk_click, install_referrer) | 49 | same 3 | 55 keys | 304 B |
| 3 | attribution (initiated_by=sdk)      | 22 | same 3 | 28 keys | 304 B |
| 4 | event (event_token=y3sjx5)          | 48 | same 3 | 54 keys | 304 B |

**Map composition**: `sign()` receives params+globals; between `sign()` and `nSign`
the Java layer merges them and appends exactly 4 fields:
`adj_signing_id=1300000`, `algorithm=adj7`, `headers_id=8`, `native_version=3.62.0`.
`endpoint=https://app.adjust.com` (a global) is consumed Java-side and is NOT in the
nSign map. The output Map gets the merged map + `authorization="Signature
signature=\"<304B hex>\"",adj_signing_id="1300000",algorithm="adj7",headers_id="8",
native_version="3.62.0"`.

### Session call — exact nSign map (order = LinkedHashMap iteration order)

```
store_name_from_system=com.android.vending
country=IN
api_level=31
hardware_name=S2SE32.28-28-4
partner_params={"payrupik_c_id":"4c2576c7-56da-3568-9d9c-dd5ef029b6c8"}
app_version=3.0.4
app_token=smxi7gqwu39c
installed_at=2026-10-06T12:10:31.567Z+0530
adj_signing_id=1300000
wait_total=0.0
device_type=phone
language=en
gps_adid=af008a79-8652-4455-b5ae-789783a06961
foreground=1
connectivity_type=1
os_build=S2SE32.28-28-4
cpu_type=arm64-v8a
retry_count=0
headers_id=8
screen_size=normal
gps_adid_src=service
algorithm=adj7
wait_time=0.0
first_error=0
native_version=3.62.0
sent_at=2026-10-06T13:00:05.465Z+0530
offline_mode_enabled=0
screen_density=high
session_count=1
ui_mode=1
enqueue_size=0
gps_adid_attempt=1
created_at=2026-10-06T13:00:05.361Z+0530
device_manufacturer=motorola
display_width=1080
device_name=moto g42
needs_response_details=1
updated_at=2026-10-06T12:10:31.567Z+0530
screen_format=long
last_error=0
os_version=12
android_uuid=b4621749-0f5b-4ce1-8881-424a0f705fff
environment=production
attribution_deeplink=1
display_height=2237
package_name=in.hanafintech
initiating_package_name=com.android.vending
os_name=android
activity_kind=session
client_sdk=android5.6.0
tracking_enabled=1
```

(click / attribution / event maps: full ordered dumps in `hanaf_map.json`
→ `captures[i].nsign_map` / `nsign_order`.)

### secret_id / per-install extra fields — the answer

**`secret_id` and `app_secret` are NOT in any sign()/nSign map** (checked all four
calls). No hidden per-install fields are added to the claims for
session/sdk_click/attribution — the claims verify byte-exact from the visible map
alone (see §3). The per-install values that DO ride along are the four Java-appended
fields above (`adj_signing_id=1300000`, `algorithm`, `headers_id=8`,
`native_version=3.62.0`) — `adj_signing_id` is not a claim-pool key (the pool law
pins "1300000" itself at the split point), so nothing extra enters the claims.

## 3. H-law verdict on the real map

For each call: `record = cbc_dec(blob[16:272], blob[:16])` (K from
`work/record_0015.json`, via `ks_inverse.py`) decrypts to the expected 256-B JSON
(`a` nonce-u64, `b` H, `c` cert40 = `C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF` —
the app's signing-cert SHA-1, matching run_hanaf.log's `c1bfafcaffb8...` prefix,
`d` nonce tail, `e` = sha256('') hex-upper).

**NEW LAW DISCOVERY (real device with cert):** the commitment message prefix is the
**cert SHA-1 as 40 ASCII bytes** (the record's `c` field), NOT `00*40`:

```
msg = cert40_ascii || nonce12 || hex-upper(sha256(b"")) || claims
H   = SHA-256 with IV0 over msg        (adj7_pure.sha256_iv0)
```

`nonce12` = `u64le(record.a) || hex-decode(record.d)` — per-signing, exactly as
`adj7_pure` assumed. Bonus cross-check: `make_header(created_at-second) ==
blob[:16]` for **all four** calls — blob↔call pairing is exact.

Verdicts (`verify_hanaf.py`, claims = `adj7_pure.build_claims(kind, captured_map)`
as-is; the map already carries activity_kind/client_sdk so `include_block2` is a
no-op):

| call | 00*40 prefix | cert40 prefix |
|---|---|---|
| session      | mismatch | **MATCH** |
| click        | mismatch | **MATCH** |
| attribution  | mismatch | **MATCH** |
| event        | mismatch | mismatch (open) |

**3/4 byte-exact MATCH.** The claims pool law (`build_claims`, pool order,
"1300000" pinned at the session_count split) is confirmed against the real SDK from
the captured maps alone — no hidden fields needed. The `event` call still mismatches:
exhausted grids (drop-1/drop-2 pool keys, add secret_id/app_secret candidates,
numeric ±perturbations, timezone/url-encoding variants, map-order walks,
adj_signing_id pin positions, out-map source) all mismatch; record structure, cert40,
nonce12 and header-second all check out, so it is a small residual in that one
call's claims (most likely a value the native read differently than our map
snapshot, or an event-only extra field). Honest status: session/tps/attribution law
= PROVEN on-device; event = open.

## 4. Delta vs our funnel session fields (adj7/run_hanaf.log)

Funnel session POST body = 46 fields; real session nSign map = 51 keys
(49 after the wire-filter of `activity_kind`/`client_sdk`).

In the REAL map, missing from our funnel session body:
- `partner_params={"payrupik_c_id":"4c2576c7-..."}`
- `initiating_package_name=com.android.vending`
- `adj_signing_id=1300000`, `algorithm=adj7`, `headers_id=8`, `native_version=3.62.0`
- (`activity_kind`, `client_sdk` — in the map, filtered off the wire)

In our funnel body, NOT in the real map (funnel over-included):
- `mcc=405`, `mnc=872`, `queue_size=0`

Value-level differences (device difference, not law difference): api_level 29→31,
os_version 10→12, device_name GM1901→moto g42, manufacturer OnePlus→motorola,
hardware_name/os_build → S2SE32.28-28-4, different gps_adid/android_uuid.
**Important timestamp-format finding:** the real SDK builds `created_at`/`sent_at`/
`installed_at`/`updated_at` in the device's LOCAL offset (`...T13:00:05.361Z+0530`),
not UTC `+0000` as our funnel emitted — and those exact local-offset strings are
what enter the claims (session MATCH proves it).

## 5. Files (adj7/work/)

- `hanaf_map.json` — full capture: 4 sign calls (params/globals/out maps + orders,
  exact nSign merged map + order, nSign & Z22222 blob hex) + 8 raw nSign records.
- `oracle_logcat.txt` — all 91 ADJ7ORACLE lines (from the LSPosed daemon log; the
  main logcat ring buffer rotated the Log.d copies out — noted in the header).
- `lsposed_modules.log` — raw source log (full copy).
- `hanaf_verify.json` — per-call record fields + verdict matrix.
- `parse_oracle.py`, `verify_hanaf.py` — reproducible parse/verify scripts.
- `full_logcat.txt` — plain logcat dump taken during diagnosis.
- `screen1..5.png` — device UI state during the flow.

Module state left on device: com.adj9oracle enabled, scoped to in.hanafintech
(+ penti/creditsea as before); pre-edit DB backup at
`/data/adb/lspd/config/modules_config.db.bak_hanaf`.
