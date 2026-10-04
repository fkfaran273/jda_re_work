# com.penti.app — Adjust signature algorithm

**Answer: `adj9`, Adjust Signature SDK 5.0.0** (native_version `5.0.0`).

> **LIVE-VALIDATED 2026-09-09** against a real on-device capture (LSPosed oracle,
> frida-free). Two real `activity_kind=event` signings were captured and the offline
> Python port (`adj9/canonical.py`) reproduces the device's canonical string
> **byte-for-byte**, and `build_authorization_header()` reproduces the full header.
> Real values: `adj_signing_id=1500000`, `headers_id=10`, `signature=Base64(nSign
> 192-byte blob)`. See "Live validation" at the bottom for details.

## Evidence chain

1. `libsigner.so` is in `split_config.arm64_v8a.apk` (not base.apk) — 1,366,632 bytes,
   md5 `dbe36c643d174f1cca240dcec1f4c585`, exporting only
   `Java_com_adjust_sdk_sig_NativeLibHelper_nSign` / `_nOnResume`.
2. Byte-identical to `com.adjust.signature:adjust-android-signature:5.0.0`
   → `jni/arm64-v8a/libsigner.so` (Maven Central). Size triage: 3.35.0 = 943,824 ·
   3.67.0 = 1,304,840 · **5.0.0 = 1,366,632** · 5.5.0 = 1,440,728.
3. Java side agrees it is v5: `com/adjust/sdk/sig/ISigner` exists, 121 obfuscated
   `a0..z2` sig classes in `classes3.dex`, plus
   `"This version of Adjust Signature is not compatible with Adjust SDK v4..."` at
   `classes3.dex + 0x74604a`.
4. Decoding `libsigner.so` `.data` (file offset `0x149c20`, va `0x151c20`) with the
   per-entry trailing-XOR-key method:

   | va | string | xor key |
   |---|---|---|
   | 0x151cc8 | `native_version` | 0xd4 |
   | 0x151cd8 | `5.0.0` | 0x17 |
   | 0x151ce0 | `adj_signing_id` | 0x25 |
   | 0x151cf0 | `algorithm` | 0xb9 |
   | **0x151cfc** | **`adj9`** | 0xbb |

   `adj8` = signature SDK 3.x (e.g. native_version 3.67.0 on derayah);
   `adj9` = signature SDK 5.x. This app is the latter.

## The algorithm (same family as adj8, new protocol revision)

1. Key: AndroidKeyStore **HmacSHA256** key, alias `key2` (non-exportable TEE key on
   API ≥ 23; a copy is RSA-wrapped into SharedPreferences `adjust_keys` → `encrypted_key`).
2. Java `Signer.sign()` builds a `HashMap` of the full activity params + injected
   `activity_kind`, `client_sdk`, and HMACs `params.toString().getBytes(UTF-8)`.
3. `NativeLibHelper.a(ctx, LinkedHashMap, hmac, SDK_INT)` → private native
   `nSign(Context, Object, byte[], int)`. It delegates the crypto to keystore2/keymint
   over `/dev/binder`, returning a **192-byte, non-deterministic** blob (fresh per call).
   (Live capture measured 192 bytes; this doc earlier said 176 — corrected 2026-09-09.)
   The `signature` header field is exactly `Base64(NO_WRAP)` of this 192-byte blob.
4. Java Base64 (NO_WRAP) → `signature`; header built by `u2.a(LinkedHashMap, byte[])`:

   ```
   Signature signature="<b64>",adj_signing_id="<id>",algorithm="adj9",headers_id="<id>",native_version="5.0.0",adj_verification="<v>"
   ```

   Six fields, fixed order — **`algorithm` precedes `headers_id`**. Confirmed twice:

   - reference AAR 5.0.0, `u2.a(LinkedHashMap, byte[])`: array slots
     `[0]=signature [1]=adj_signing_id [2]=algorithm [3]=headers_id
     [4]=native_version [5]=adj_verification`
   - the app's own `classes3.dex`, `u2.a` @ `0x36a97c`:
     `filled-new-array/range {v14,v15,v16,v17,v18,v19}` with
     `v14=signature v15=adj_signing_id v16=algorithm v17=headers_id
     v18=native_version v19=adj_verification`

   > Correction: an earlier revision of this file claimed 5.x puts `headers_id`
   > before `algorithm` and that 3.x differs. Both statements were wrong. 3.x
   > differs only by **omitting `adj_verification`**; the order is otherwise the same.

   If any of the six values is null, `u2.a` logs "Required value was null." and
   returns null — the request then goes out unsigned rather than failing.
   Body is `x-www-form-urlencoded` to `https://app.adjust.com/session` etc.;
   booleans are `1`/`0`.

### Canonical string (corrected — this is what is actually HMAC'd)

From `javap` on `com.adjust.sdk.sig.u2`:

```java
LinkedHashMap out = new LinkedHashMap<>(activityParams);   // copy keeps source order
out.put(globalParams...);
out.put("adj_verification", o3.a(new a0()));
byte[] hmac = t1.a(ctx, out.toString().getBytes(UTF_8));   // keystore HMAC-SHA256
```

So it is a `LinkedHashMap.toString()` (insertion order) — but its prefix is a copy of
the SDK's source **HashMap**, which is in bucket order. Both halves matter; a Python
port modelling only one of them will produce a plausible but wrong string.
`adj_verification` is inserted *before* the HMAC, so it is part of the signed input.

### adj_verification is decodable offline

`adj_verification = o3.a(new a0())` — despite sitting next to the TEE-backed
signature, it has **nothing to do with the keystore**. `o3.a` (5.0.0 bytecode):

```java
String s  = new o1(...).toString();          // serialize the a0 state object
byte[] b  = d3.a(s);                          // UTF-8 bytes
for (int i = 0; i < b.length; i++)            // repeating 19-byte XOR
    b[i] ^= s2.a[i % 19];
return Base64.encodeToString(b, NO_WRAP);
```

`s2.a` is a 19-byte constant read straight out of `s2.<clinit>`:

```
51 75 6F 68 38 75 61 66 6F 68 67 68 37 43 61 68 4D 32 68
"Q  u  o  h  8  u  a  f  o  h  g  h  7  C  a  h  M  2  h"
== b"Quoh8uafohgh7CahM2h"
```

Identical in the reference AAR **and in this app** — `classes3.dex`,
`s2.<clinit>` uses `fill-array-data` at `0x36a7f8` → `51 75 6F 68 38 75 ...`.

So a captured header's `adj_verification` decodes to plaintext with
`decode_adj_verification()` in `adj9/canonical.py`. It is the SDK's
device/environment integrity report (serialized `a0`), **not** a signature —
worth decoding any real capture to see exactly what it phones home.

## Signed fields (decoded from the native table, ~100 entries)

ad_impressions_count, ad_revenue_network, ad_revenue_placement, ad_revenue_unit,
adj_verification, adgroup, adjust_product_id, adjust_transaction_id, android_id,
android_uuid, api_level, app_secret, app_token, app_version, app_version_short,
att_status, bundle_id, callback_params, campaign, click_time*, country, created_at,
creative, currency, deduplication_id, default_tracker, details, device_*, environment,
event_*, external_device_id, fb_*, ff_*, fire_adid, fire_tracking_enabled,
found_location, google_play_instant, gps_adid*, granular_third_party_sharing_options,
hardware_name, idfa, idfv, initiated_by, initiating_package_name, install_*,
installed_at, is_system_app, is_updated_system_app, last_skan_update, mcc, measurement,
mnc, needs_cost, odm_info, order_id, originating_package_name, os_*, package_name,
params, partner_*, payload, payloads, payment_backend, primary_dedupe_token,
purchase_*, push_token, referrer*, reftag, revenue, sales_region,
secondary_dedupe_token, **secret_id**, seq, session_count, session_length, sharing,
skadn_registered_at, snapshot_hash, source, started_at, store_*,
subsession_count, time_spent, tracker, tracking_enabled, updated_at, user_id,
**activity_kind, client_sdk, headers_id, native_version**.

## Live validation (2026-09-09)

On-device capture via the LSPosed oracle (`adj9/module/`, frida-free — the frida route
was abandoned after proving bare `Java.perform` is killed by the app's anti-frida
guard). Validator: `adj9/verify/validate_real.py` on `adj9/device/capture_oracle_*.log`.

Two real `activity_kind=event` signings (`event_token=p90b20`, `29ah7d`). Per event the
oracle logged: `d3.a` canonical string (HMAC input), `o3.a` adj_verification,
`NativeLibHelper.a` nSign blob, and the `u2.a` output header.

Confirmed against ground truth:
- **Canonical string**: `canonical_string_v5()` matches **byte-for-byte** (both
  `source_capacity` 16 and 64 — for 47 source keys both settle at 64 buckets). Split
  is `source=47 fields + globals={activity_kind, client_sdk} + adj_verification`.
- **HMAC input excludes the 4 metadata fields.** The `d3.a` string ends at
  `adj_verification=...}`; `headers_id`, `adj_signing_id`, `native_version`,
  `algorithm` appear only in the 54-field map `u2.a` receives and in the header —
  they are NOT HMAC'd. (Matches the "adj_verification is inserted before the HMAC"
  analysis and pins down exactly where signing stops.)
- **`signature` = Base64(NO_WRAP) of the 192-byte nSign blob** (nsign hex ==
  u2.a `key2` byte[] arg == decoded signature field). Blob is 192 bytes, not 176.
- **Header order** reproduced exactly by `build_authorization_header()`.
- Real constants: `adj_signing_id=1500000`, `headers_id=10`,
  `adj_verification=KlcAG2cbAAsKSl1KVi0FGiJbDHMI` (constant across both events),
  `app_token=jut9tib0eeps`, `client_sdk=android5.7.0`, `app_version=3.12.1`.

Caveat for forging NEW params: feeding the source keys in alphabetical order does NOT
reproduce the device string — there ARE bucket collisions (e.g.
`hardware_name`/`partner_params`/`app_version`), so the SDK's real HashMap *insertion*
order governs within-bucket order. The model is correct given the correct insertion
order; to mint signatures for arbitrary param sets you must feed the SDK's actual
put() order (recoverable from the dex), not a guessed order. Signing itself still
requires the device (non-exportable `key2`).

## Notes / caveats

- The lib carries a large emulator/Frida detector (`TracerPid:`, `ro.kernel.qemu.*`,
  `/dev/qemu_pipe`, Bluestacks/Nox/MEMU/Goldfish markers, `isInsideSecureHardware`).
  Signing is skipped or fails on instrumented devices.
- To mint signatures you must go **through a real device** (frida RPC into
  `Signer.sign()`); the keystore key cannot be extracted on API ≥ 23. The API 18–22
  software fallback in `com.adjust.sdk.sig.c` does expose the raw key.
- Two dead ends worth remembering: whole-dex single-byte XOR sweeps for `adj9` return
  false hits inside a MathJax HTML-entity table in `classes7.dex`; and a second,
  per-build alphabet-scrambled string layer in `.rodata` (`SAFWKGOAP`, `KJJAGPMKJ`)
  is not recoverable statically.
