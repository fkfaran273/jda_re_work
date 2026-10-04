# adj9 signing pipeline — runtime-confirmed (2026-09-09)

Everything below was observed on-device with the LSPosed oracle module
(`adj9/module/`), scoped to `com.penti.app`. No guessing: every line is backed by
a captured JCA call. Raw captures live in `adj9/cap/`.

---

## 1. Bottom line

```
signature = Base64(NO_WRAP)( nSign(ctx, obj, H, apiLevel) )        // 192 B -> 256 chars
      H   = HMAC-SHA256(canonical_payload, key2)                   // 32 B
  key2    = AndroidKeyStore entry "key2", HMAC-SHA256, 256-bit,
            PURPOSE=SIGN, ORIGIN=GENERATED, non-exportable
```

`key2` is **generated inside the keystore at first app launch** and can never be
read out — by the app, by us, or by anybody else (evidence in §4). That is the
single, complete blocker for offline signing.

---

## 2. The captured call sequence

Captured for `activity_kind=session`, `created_at=2026-09-09T11:17:44.961Z+0200`.
All timestamps are the module's `ts=` (epoch ms).

| # | call | value |
|---|------|-------|
| 1 | `d3.a` (canonical) | `{"os_name":"android"}` |
| 2 | `o3.a` (adj_verification) | `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` |
| 3 | `KeyStore.getInstance` | `AndroidKeyStore` |
| 4 | `KeyStore.load` | `null` |
| 5 | `KeyStore.containsAlias` | `key2` → **true** |
| 6 | `d3.a` (canonical) | **1357-byte** payload string (see §3) |
| 7 | `Mac.getInstance` | `HmacSHA256` (provider AndroidOpenSSL) |
| 8 | `KeyStore.getKey` | `key2` → `android.security.keystore2.AndroidKeyStoreSecretKey`, alg=`HmacSHA256`, **format=null, encoded=null** |
| 9 | `Mac.init` | the key above |
| 10 | `Mac.update` | **len=1357** — byte-identical to the canonical string |
| 11 | `Mac.doFinal` | **32 B** `9e2f0fc038ec069c433b1dee741be954c7f20eb2dd5d886825b15704322f5ff9` |
| 12 | **`NativeLibHelper.a` (nSign) entry** | `arg3_len=32 arg3_hex=9e2f0fc0…5ff9  arg4_int=31` |
| 13 | (inside nSign) `MessageDigest` | `SHA1` ×3, all → `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` |
| 14 | (inside nSign) `KeyStore.getKey` | `key2` (new object `@3fab7cef`) |
| 15 | (inside nSign) `Mac` HmacSHA256 → `doFinal` | **32 B, identical to step 11** |
| 16 | (inside nSign) `KeyStore.getInstance` | `BKS` / provider `BC` 1.77 |
| 17 | (inside nSign) `MessageDigest` | 3 × (MD5, SHA-1, SHA-256) — see §5 |
| 18 | **`nSign` returns** | **192 B** → base64 `IjtvbmSTSFEdyeYecKsWpAAjsn4QHGjSRzv7DGGyiZJI…` |
| 19 | map handed to header builder | 54 entries (50 payload + 4 header fields) |
| 20 | `Base64.encodeToString(192 B, flags=2)` | the `signature=` value |

So: **nSign is called with the HMAC already computed.** It does not compute the
MAC for the caller — it recomputes it (step 15) purely as an internal check, then
wraps/expands the 32 bytes into 192.

---

## 3. What exactly gets MAC'd

The 1357-byte string is the SDK's serialization of its `LinkedHashMap`
(`{k=v, k=v, …}`, insertion order — i.e. Java `Map.toString()` with no spaces
after commas). It contains **50** entries and *includes* `adj_verification`.

It does **not** contain the four header fields. Those are inserted into the map
*after* `nSign` returns, which is why `sign_input` shows `map_size=54`:

```
…, client_sdk=android5.7.0, adj_verification=KlcAG2cbAAsKSl1KVi0FGiJbDHMI}   <- 50, signed
   + headers_id=10, adj_signing_id=1500000, native_version=5.0.0, algorithm=adj9   <- 54, not signed
```

### adj_verification is a constant

```
Base64( XOR(UTF8('{"os_name":"android"}'), b"Quoh8uafohgh7CahM2h", i % 19) )
  = KlcAG2cbAAsKSl1KVi0FGiJbDHMI
```

Verified by decoding the captured value back to `{"os_name":"android"}` (21 B).
The input map is fixed, so **adj_verification is the same string for every
Android request from every app**. It carries no per-request information.

---

## 4. key2 — provenance (the decisive fact)

Read straight out of `/data/misc/keystore/persistent.sqlite`
(copy in `adj9/device/ks/persistent.sqlite`), `keyentry` where
`namespace = 10392` (uid of `com.penti.app`, `u0_a392`):

```
alias     = key2                     (the only other alias is androidx's)
ALGORITHM = 128  (HMAC)
ORIGIN    = 0    (GENERATED)     <-- not IMPORTED, not DERIVED
PURPOSE   = 2    (SIGN)
DIGEST    = 4    (SHA-2 256)
KEY_SIZE  = 256 bits
MIN_MAC_LENGTH = 256
NO_AUTH_REQUIRED present
sec_level = 1 (TEE)
created   = 2026-09-08 12:07:27 UTC  == first launch after install (12:07)
```

Cross-check across the device — **10 apps** ship the Adjust signature SDK and all
ten have the same entry:

```
uid      alg    origin      bits  digest   created(UTC)
10312    HMAC   GENERATED   256   4        2026-09-08 05:56:28
10340    HMAC   GENERATED   256   4        2026-08-27 05:26:13
10344    HMAC   GENERATED   256   4        2026-08-24 07:53:25
10350    HMAC   GENERATED   256   4        2026-08-25 11:49:55
10356    HMAC   GENERATED   256   4        2026-08-26 10:02:54
10374    HMAC   GENERATED   256   4        2026-09-06 18:02:54
10375    HMAC   GENERATED   256   4        2026-09-04 16:20:50
10376    HMAC   GENERATED   256   4        2026-09-05 08:57:05
10390    HMAC   GENERATED   256   4        2026-09-08 09:09:01
10392    HMAC   GENERATED   256   4        2026-09-08 12:07:27   <- com.penti.app
```

Zero `IMPORTED`. Corroborated in-process: `Key.getFormat()` and
`Key.getEncoded()` both return **null** (captured in `jca_ks_getKey` /
`jca_mac_init`).

**Consequence:** the key material came into existence inside the secure element
and has never existed anywhere else. No party — not the app process, not a
rooted adb shell, not Adjust's backend — can obtain it.

---

## 5. Inside nSign — digests, the AES layer, and the envelope (updated 15:30)

### 5a. Corrections to the first read of this data

1. **There is no "~490 ms hidden stall".** Correct timestamps from capture6:
   window 0 last JCA op at +343 ms, return at +813 ms (470 ms gap — logging/pull
   latency, zero ops in it); window 1 last cipher at +691 ms, return at +693 ms.
   **nSign returns ~immediately after its last JCA call.**
2. **The digest inputs are not a stable fingerprint.** Window 0 hashed X.509
   fragments of `CN=api.personalclick.com`, ISRG Root X2/Y2, Let's Encrypt E2,
   EC P-256/P-384 key BIT STRINGs and the 1095 B `CN=Android0` (Google) cert.
   Window 1 hashed a *different* set: `CN=upload.video.google.com`, GTS Root R1,
   WR2, different EC keys. The common shape (745 B app cert first, then NIS
   rounds over X.509 fragments) says nSign walks the **system trust store**
   (`/system/etc/security/cacerts`) in non-deterministic order — the fragments
   are just SPKI/issuer DER pieces of whichever roots it iterates. Only the
   SHA-1 of the app signing cert (`fad0f10d…`) is a stable, per-app value.

### 5b. New: the AES layer (visible only in window 1)

Immediately before returning, nSign ran 10 `Cipher.doFinal` with RAW
`SecretKeySpec` AES-256 keys:

```
K1 = 3cd000451739baaac19dcc1f3f686d0dc302cacdd32be061eb842100c4f28f48  (6 inits)
K2 = f065595e09288254f06195ac44cb3e1917c217bca57fea117de05149475ac05b  (2 inits)
```

Plaintexts: `user_session`, `session_token`, `core_network_ses`, and 16-byte
binary blocks; outputs equal inputs in length (12/13/16 B) → ECB mode, not an
envelope-sized encryption.

**Attribution check (false-positive guard):** identical ops with the *same keys*
occur all over the capture outside nSign, encrypting app pref names
(`pref.user.customer.id`, `access_token`, `refresh_token`, `first_app_open`,
…). That is the app's androidx **EncryptedSharedPreferences**; its pref-DB AES
keys are hardcoded, and nSign's window simply overlapped a prefs flush. Decisive
counter-evidence: **window 0 performed zero cipher ops and still emitted a
192-byte envelope.** → K1/K2 are NOT envelope keys; the AES layer is not the
envelope construction. The 32→192 transform is native-only (never surfaces in
JCA).

### 5c. Envelope correlation (all negative, now complete)

Across the two new envelopes D (window 0) and E (window 1) plus A/B/C:

* D↔E share a 0-byte prefix — even same-session envelopes are unrelated at the
  byte level.
* The HMAC H (arg3), every internal digest, K1, K2, and every captured cipher
  input/output appear **nowhere** inside any envelope (byte-substring search).
* No repeated 16-byte blocks → not plain ECB over low-entropy input.
* Byte histogram 128–140 distinct values / 192 B → high-entropy, encrypted.

Conclusion: the envelope is constructed entirely inside the obfuscated native
code from inputs that include H, the canonical payload, the app-cert digest,
and trust-store material. Its exact layout remains open — but reversing it is
analysis work; it cannot be produced offline because the HMAC input (H) comes
from the non-exportable TEE key (§4).

---

## 6. What Adjust's backend actually verifies (given it cannot know key2)

Since key2 is GENERATED inside the TEE (§4), Adjust's servers can never
recompute `H = HMAC-SHA256(canonical, key2)`. So verification is necessarily
indirect. The evidence points to:

1. **The envelope is decryptable server-side.** The 192 B blob is produced by
   native code (§5) with no secret that ever leaves the TEE going *into* it
   beyond H. A scheme where the server holds the corresponding key (or the
   obfuscated .so carries an encoded server key — its 511 `.data` strings and
   flattened CFG hide exactly this kind of constant) fits every observation:
   high entropy, no plaintext structure, no JCA-visible construction.
2. **What the decrypted envelope can contain** (all observed on-device):
   `H` itself (32 B, device-consistency tag — same request signed twice on the
   same device yields the same H), a hash of the canonical payload, the app
   signing-cert digest (`fad0f10d…`, SHA-1, stable per app), trust-store /
   TLS-environment material, and `apiLevel`.
3. **Server-side checks that do not need key2:** envelope decrypt + field
   validation; `adj_signing_id=1500000`, `headers_id=10`, `native_version`,
   `algorithm=adj9` gating; `adj_verification` constant correctness; the
   canonical payload matching what the envelope says was signed; app-cert
   digest vs. the certificate the server knows for this app; and TLS-level
   identity of the connection.
4. **The HMAC's role is anti-tamper inside the envelope, not a verifiable MAC
   at the server.** A forged envelope would have to contain an H consistent
   with the claimed canonical payload — but the forger cannot compute H for
   any *new* payload, and cannot produce envelope bytes Adjust will decrypt
   successfully without reversing the native scheme.

Net: "what they verify" = server-side decryption + consistency of the envelope
contents with the visible request. The un-determined part is the exact native
32→192 transform and the envelope field layout.

---

## 7. Corrections to earlier notes

1. **`key2_len=192` in my earlier capture was mislabelled.** It is the `byte[]`
   argument of `u2.a(map, k)` == nSign's **return value**, not a key length.
   key2 itself is 256 bits and unreadable.
2. **`adj_verification` is not payload-derived.** Its input is the fixed map
   `{"os_name":"android"}`, so it is a per-platform constant.
3. The SDK computes the HMAC **in Java**, before calling nSign; nSign recomputes
   it internally. Two `Mac` instances per request, same output.
4. (15:30) The "~490 ms stall after the last digest" was a logging-latency
   artifact — see §5a.
5. (15:30) The per-session digest inputs are trust-store walk output, not a
   stable device fingerprint — see §5a. The AES ops seen inside nSign belong to
   the app's EncryptedSharedPreferences, not the envelope — see §5b.

---

## 8. Tooling used

| file | purpose |
|------|---------|
| `adj9/module/src/com/adj9oracle/Hook.java` | LSPosed module: hooks `d3.a`, `o3.a`, `NativeLibHelper.a` **and** `javax.crypto.Mac / Cipher` / `java.security.KeyStore` / `MessageDigest` / `SecretKeySpec` / `Base64`; `[inside nSign]` prefix is set while nSign is on the stack |
| `adj9/module/build.sh` | builds + signs it (keystore is now preserved across builds) |
| `adj9/device/ks/persistent.sqlite` | copy of keystore2's DB, used for the ORIGIN proof |

Deployment notes (this bit me twice):

* `adb install -r` fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE` unless the
  debug keystore is reused — `build.sh` now keeps `build/debug.keystore`.
* After (re)installing, LSPosed re-registers the module with a **new `mid`** but
  leaves it `enabled=0` and drops the scope row. Until that is fixed the module
  is silently inactive. Fix: pull
  `/data/adb/lspd/config/modules_config.db{-wal,-shm}`, set
  `modules.enabled=1` for the new mid, repoint `scope` to it, push back, delete
  the `-wal`/`-shm`, `chmod 660`, reboot.
* Signing only happens when Adjust starts a **new session** (gap since last
  activity > session interval). Force-stop + relaunch a few minutes later will
  *not* sign. A fresh boot will. The module now also probes the keystore
  directly at startup so key metadata can be read without waiting for a session.
