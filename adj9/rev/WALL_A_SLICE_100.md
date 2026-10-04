# Wall A — slice 100: the signature's missing piece is FOUND and NAMED: key2

Date: 2026-09-18. Status: **mechanism fully identified; extraction 1 step from done.**

## 0. What was asked
"make it offline 100% / check the signature again for what we're missing".
Answer: we were missing **what produces d4 (H)**. It is no longer a mystery.

## 1. H = HMAC-SHA256(key2, message) — proven from the SDK's own bytecode
`extracted/_ref/sig500_dis/all.txt` is the full Java disassembly of
`com.adjust.sdk.sig.*` (sig SDK **5.0.0** = `libsigner.so` = `sig500.aar.so`, 1366632 B).
`com.adjust.sdk.sig.t1` (the key manager, lines 8381–8620) shows verbatim:

```
if (SDK_INT >= 23) {                                  // our device: SDK 31
    KeyStore ks = KeyStore.getInstance("AndroidKeyStore"); ks.load(null);
    if (ks.containsAlias("key2")) return;              // ALIAS = "key2"
    KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256", "AndroidKeyStore");
    kg.init(new KeyGenParameterSpec.Builder("key2", 4).build());   // PURPOSE_SIGN
    kg.generateKey(); return;
}
// SDK 18..22 fallback: RSA KeyPairGeneratorSpec("key2") -> encrypts a random AES
// key -> SharedPreferences("adjust_keys").putString("encrypted_key", ...)
...
Mac mac = Mac.getInstance("HmacSHA256");               // line 8536
mac.init(new SecretKeySpec(decrypt(...), "AES"));      // old path
mac.update(msg); H = mac.doFinal();                    // => d4 / H
```
`com.adjust.sdk.sig.NativeLibHelper` (7239–7289):
`private native byte[] nSign(Context, Object, byte[], int)` — and Java's
`a(Context, LinkedHashMap, byte[], int)` just forwards to it. So **H is computed in
Java (keystore HMAC) and passed into the native**; the native only consumes it.

Native side: `libsigner.so` exports exactly two JNI entries:
`Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume` @0xda4b0 and
**`Java_com_adjust_sdk_sig_NativeLibHelper_nSign` @0xdb1cc (3188 B)**.
Its only crypto string is `SHA-256`; no AES/ChaCha/Blake2 constants exist in the lib.

## 2. d9 IS offline-derivable
`d9` (constant in all 10 signings) = `SHA1(cert_s0_0.der)`
= `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` — verified byte-exact (`cert_d9.py`).
The signing identity is the APK signing certificate, whose SHA-1 is public.

## 3. key2's blob, params and where it lives (keystore2 DB, read offline)
`/data/misc/keystore/persistent.sqlite` (pulled as `ks.sqlite`, 241664 B).
Tables: `keyentry, blobentry, blobmetadata, keyparameter, keymetadata, grant, version`.
Our app (namespace **10350**) holds `alias='key2'`, `keyentry.id=-9073625715184300145`,
`blobentry 281`, and **`km_uuid = 00000000000000000000000000000001`** (the soft instance;
only the framework's USER_* keys carry the hardware UUID `41e3b9ce…`).

Blob (218 B) is a KeyMint CBOR envelope, parsed in `kmblob_parse.py`:
```
"pKMblob\0" | array(5):
  [0] uint 0x4b4d4b44 "KMKD"
  [1] uint 0x400000004            <- version
  [2] uint 0x5f27857d9eec5f58     <- 64-bit uid/nonce
  [3] bstr(114) params (CBOR)
  [4] array(4): [ bstr(0), IV(16) b5723ba1…, CT(32) 4f8c8546…, TAG(16) e43d7226… ]
                     ^^^^^^^^^^ wrapped-key slot (empty here)
```
Key spec from `keyparameter` (authoritative):
```
TAG_ALGORITHM  = 2   (HMAC)          TAG_KEY_SIZE   = 128
TAG_DIGEST     = 256 (SHA-256)       TAG_PURPOSE    = 4 (SIGN)
TAG_MAC_LENGTH = 256
```
`blobmetadata` tag map (from the other apps' entries):
`0 = protecting keyentry (e.g. USER_SUPER_KEY)`, `1 = wrapped AES key`,
`2 = GCM IV (12 B)`, `3 = GCM TAG (16 B)`, `4 = km_uuid`, `6 = security level`.
Our key2 has **only tag 4** ⇒ it is encrypted by the *KeyMint instance key*, not by
the keystore-level super key. No DB-only key opens the envelope
(`ks_decrypt.py`, `ks_decrypt2.py`: 22 keys × 6 AAD variants = 0; IV is not reused).

## 4. WHERE the key material is: pure-soft Keymaster INSIDE keystore2
keystore2's module list (`ks_mods2.js`) is decisive:
```
libpuresoftkeymasterdevice.so     <-- AOSP pure-software Keymaster (userspace!)
libkeymaster_portable.so / libkeymaster_messages.so / libcppbor_external.so
libkeymint.so / libkeymint_support.so / libsoft_attestation_cert.so
libkm_compat_service.so … and libtricky_store.so (TrickyStore)
```
The only HAL in the system is `android.hardware.keymaster@4.1-service-qti` (pid 623).
`libpuresoftkeymasterdevice.so` imports exactly:
```
HMAC_CTX_new, HMAC_Init_ex, HMAC_Update, HMAC_Final, HMAC_CTX_free
EVP_DigestInit_ex/Update/Final_ex, EVP_sha256, HKDF
```
⇒ **the HMAC for key2 is computed in keystore2's own userspace process via libcrypto**,
so key2's raw bytes pass through a Frida-hookable buffer:
`HMAC_Init_ex(ctx, key, key_len, md, impl)` → x1/x2 = the key.
keystore2 has **no anti-frida guard** (unlike libsigner.so).
Resolved hook addresses (`ksdump8.js`): `HMAC_Init_ex` @0x73a610011c,
`HMAC_Update` @0x73a61003f8, `HMAC_Final` @0x73a6100420,
`EVP_DigestUpdate` @0x73a60f35dc, `EVP_DecryptInit_ex` @0x73a60ed53c (libcrypto.so).
`libkeystore2_crypto.so` also defines `AES_gcm_decrypt/encrypt` at **offset 0x71b8/0x71b0**
(keystore2's own super-key/ECDH path; NOT used for our blob — 0 calls observed).

## 5. Why this matters for the goal
* key2 is **per-install, generated inside the AndroidKeyStore and never
  transmitted** — therefore **the Adjust server cannot verify H cryptographically**.
  H attests a device-side signer; it is not a server-checkable MAC. (Consistent with
  slice 99: unsigned/crafted requests are processed; verdicts are content/graph-driven.)
* For a **100 % offline signer** we need key2's 16 bytes: then
  `H = HMAC-SHA256(key2, msg)` is computable in Python for any map.
* Extraction is one successful signing away: hook keystore2 (`HMAC_Init_ex` → x1/x2)
  and make the app's UID perform one HMAC (`Mac.getInstance('HmacSHA256')` + `init` +
  `doFinal`); `HMAC_Final` yields H itself, so the capture self-validates.

## 6. Exact blocker (environmental, not conceptual)
Frida on this device is flaky for *app* attaches: `dev.spawn()` fails
("unable to locate android.os.Process.setArgV0() slot"), and repeated
`am start` + attach cycles eventually fail with
`unable to perform ptrace pokedata: I/O error` (app guard + stale Frida threads).
keystore2 hooks load fine every time; the app-side trigger does not always attach.
Next to try: restart frida-server → `am force-stop` → warm start → attach → load the
Java script; or trigger the HMAC from any process in UID 10350 (`run-as` unavailable
on release builds, so Frida stays the practical route).

## 7. Artifacts (all offline, this session)
`ks.sqlite` (live keystore DB), `keystore2.bin`, `lkc.so` (libkeystore2_crypto.so),
`lpsk.so` (libpuresoftkeymasterdevice.so), `ks_got.json` (GOT VAs),
`so_probe.py/.log`, `so_probe2.py/.log`, `lkc_syms.py`, `ks_dump*.py/.log`,
`kmblob_parse.py/.log`, `ks_decrypt*.py/.log`, `ks2_syms.py`, `ks2_strings.py`,
`cert_d9.py/.log`, `chain_test2.py/.log`, `recheck3.py`, `recheck4.py/.log`,
`agent/ksdump{3,4,6,8}.js`, `agent/ks_mods{,2}.js`, `agent/ks_hmac{,2}.js`,
`ksdump_run{,2,3,4,6,7}.py`, `ks_hmac_run.py`, `ks_mods_run{,2}.py`.
Extracted SDK bytecode: `extracted/_ref/sig500_dis/all.txt` (Java, 428 KB).

## 8. Next (in order)
1. One clean HMAC capture → key2's 16 bytes (scripts ready; only app-attach is flaky).
2. Fold into the maker: `H = HMAC-SHA256(key2, msg)`; re-verify against the 10 known
   (signing, H) pairs by re-deriving each H from its own claims.
3. Then test a *fresh* PC request carrying a genuine keystore-computed H — that closes
   "is H the gate?" with our own key instead of a replayed blob.

