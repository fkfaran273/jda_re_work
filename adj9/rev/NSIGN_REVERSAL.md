# `libsigner.so` → `nSign` — static reversal (2026-09-09)

Target: `extracted/arm64/lib/arm64-v8a/libsigner.so` (1,366,632 bytes, aarch64, stripped)
Export: `Java_com_adjust_sdk_sig_NativeLibHelper_nSign` @ **VMA `0xdb1cc`, size 3188**
(companion export `nOnResume` @ `0xda4b0`, size 4 — a stub)

---

## 1. Bottom line

`nSign` does **not** implement any crypto. It is an O-LLVM-flattened JNI driver that
performs the HMAC by **reflecting into the platform JCA from native code**:

```
KeyStore.getInstance("AndroidKeyStore")  ->  load(null)
        ->  getKey("key2", null)              // non-exportable, TEE-backed
Mac.getInstance("HmacSHA256") -> init(key2) -> update(canonical) -> doFinal()
```

Every one of those class/method/signature strings is present, obfuscated, in the `.so`'s
`.data` section, and the strings are **decrypted in place by the code that uses them**.

Consequences:

* There is no HMAC implementation and no key material in native code to recover.
* The key never exists as bytes in the app process — it is an AndroidKeyStore handle.
* Even a perfect reversal of `nSign` yields no offline signing capability.

---

## 2. Evidence

### 2.1 No crypto library, no crypto code

`DT_NEEDED`: **only** `liblog.so`, `libm.so`, `libdl.so`, `libc.so`.
72 imports, all libc/pthread/stdio/socket — no `libcrypto`, no `libssl`,
no `libjavacrypto`, no keystore client lib.

Scanned the whole file for the SHA-256 `K` table and `H` init words
(`0x428a2f98`, `0x71374491`, `0xb5c0fbcf`, `0xe9b5dba5`, `0x6a09e667`, …),
the SHA-512 64-bit constants, and 16-byte runs of HMAC `ipad`(0x36)/`opad`(0x5c):
**none present.** There is no SHA-2 or HMAC implementation in this binary.

### 2.2 The obfuscated string table

`.data` @ VMA `0x151c20`, size `0x360a` (file off `0x149c20`).

Encoding (derived, then *confirmed against the code* — see 2.3):

```
[ ciphertext bytes, INCLUDING the terminating NUL ]   <- each byte XOR key
```

Because the plaintext's last byte is `0x00`, the **last ciphertext byte equals the key**.
Entries are packed back-to-back with zero padding between groups; there is no length
prefix and no separate key byte.

Decoder: `adj9/rev/strings2.py` (DP segmentation) and the anchored greedy in
`adj9/rev/strings_final.pkl` (511 strings recovered).

JCA / keystore entries recovered (VMA, XOR key, plaintext):

| VMA | key | string |
|---|---|---|
| `0x1536c0` | `0xeb` | `AndroidKeyStore` |
| `0x153720` | `0x36` | `java.security.NoSuchAlgorithmException` |
| `0x153750` | `0x94` | `android.security.keystore.StrongBoxUnavailableException` |
| `0x153788` | `0x04` | `Ed25519` |
| `0x153794` | `0xb5` | `RSA` |
| `0x1537a0` | `0xc8` | `android/util/Base64` · `decode` · `(Ljava/lang/String;I)[B` |
| `0x1537f0` | `0x52` | `javax/crypto/Cipher` · `getInstance` · `(Ljava/lang/String;)Ljavax/crypto/Cipher;` |
| `0x15384c` | `0xd2` | `init` · `(ILjava/security/Key;)V` |
| `0x153878` | `0xd1` | `doFinal` · `([B)[B` |
| `0x153890` | `0xaf` | `java/util/HashMap` · `<init>` · `put` · `remove` |
| `0x153980` | `0xff` | `android/security/keystore/KeyGenParameterSpec$Builder` · `build` · `setAttestationChallenge` |
| `0x153b60` | `0xb9` | `generateKeyPair` · `()Ljava/security/KeyPair;` |
| `0x153b90` | `0x6d` | `java/security/KeyPairGenerator` · `initialize` |
| `0x153c70` | `0x0f` | `java/security/KeyFactory` · `getKeySpec` |
| `0x153d40` | `0xd4` | `android/security/keystore/KeyInfo` · `getSecurityLevel` · `isInsideSecureHardware` |
| `0x153db0` | `0xeb` | `getCertificateChain` |
| `0x153e10` | `0xf4` | `java/security/KeyStore` · `getKey` · `(Ljava/lang/String;[C)Ljava/security/Key;` |
| `0x153f90` | `0x1c` | `javax/crypto/Mac` · `(Ljava/lang/String;)Ljavax/crypto/Mac;` |
| `0x153fe0` | `0xc5` | `(Ljava/security/Key;)V` · `update` · `([B)V` |
| `0x154040` | `0x69` | `java/security/MessageDigest` |
| `0x154480` | `0xff` | `javax/crypto/spec/SecretKeySpec` · `([BLjava/lang/String;)V` |
| `0x1547d8` | `0xe8` | `ANDROID_ID` · `advertising_id` |
| `0x1547f8` | `0xcd` | **`HmacSHA256`** |
| `0x154810` | `0x24` | **`AndroidKeyStore`** |
| `0x154820` | `0x1b` | **`key2`** ← the keystore alias |
| `0x154830` | `0x11` | `RSA/ECB/PKCS1Padding` |
| `0x154848` | `0x59` | `adjust_keys` ← SharedPreferences name |
| `0x154858` | `0xf5` | `encrypted_key` ← pref key |
| `0x154868` | `0x40` | `AES` |
| `0x154880` | `0x33` | `sandbox` (anti-emulation; decrypted *inside* nSign, see 2.4) |

Plus the full anti-emulation set (`init.vbox86.rc`, `init.nox.rc`, `/sys/qemu_trace`,
`ro.hardware.egl`, `sdk_google_phone`, `MonkeyRunner`, `/proc/self/maps`,
`/proc/%d/status`, `AgentController`, `injector`, …) and telemetry
(`getSharedPreferences`, `getPackageInfo`, `getApkContentsSigners`,
`Settings$Secure`, `DisplayMetrics`, …).

### 2.3 Strings are decrypted in place — proof

Harvested 57 such blocks (`adj9/rev/decryptors.py`). Canonical shape:

```
0x000d82c8  adrp   x8,  #0x154000
0x000d82d0  movi   v1.16b, #0x24        ; XOR key
0x000d82dc  ldr    q0,  [x8, #0x810]    ; 16 ciphertext bytes @ 0x154810
0x000d82e8  eor    v0.16b, v0.16b, v1.16b
0x000d82ec  str    q0,  [x8, #0x810]    ; plaintext written back
0x000d82f4  strb   w8,  [x10, #0xd7d]   ; "already decrypted" flag in .bss
```

`0x154810 ^ 0x24` = `"AndroidKeyStore\0"` — exactly the encoding model in 2.2.
The keys recovered from `movi` match the independently-decoded strings
(`0x24`/`AndroidKeyStore`, `0xeb`/`AndroidKeyStore`, `0xb9`/`generateKeyPair`, …).

### 2.4 `nSign`'s body

`nSign` (`0xdb1cc`–`0xdbe40`, 3188 B) is a control-flow-flattened dispatcher: opaque
predicates (`csel` on `cmp`), constants built with `mov`/`movk`, a single back-edge
dispatch block. It makes 7 direct `bl` calls (`0x95fc4`, `0xbb548`, `0xda97c`,
`0xe2be0`, `0x13d874`, `0x13de90`, `0x1483e0`) and one import (`__stack_chk_fail`).
It passes `JNIEnv* x19` into `0x95fc4`.

It also decrypts a string *inline*, at `0xdb81c`:

```
0x000db81c  adrp   x11, #0x154000
0x000db834  ldr    d0, [x11, #0x880]
0x000db844  eor    v0.8b, v0.8b, v10.8b
0x000db848  str    d0, [x11, #0x880]      ; 0x154880 ^ 0x33 = "sandbox"
```

i.e. `nSign` runs an emulator check as part of signing.

**CFG crawl** (`adj9/rev/cfg.py`, follows every direct branch and descends into every
`bl`): 7,608 blocks / **255,475 instructions** reachable, spanning `0x8c30`–`0x1489b0`
— essentially the entire `.text`, hitting 320 internal call targets and 68 of the 72
imports. The obfuscator merged the whole library into one flattened web, so *static*
call-graph slicing cannot isolate "the signing part"; the identification above rests on
the string table + the JNI reflection helper (`0xe2be0`, which loads essentially the
whole `JNINativeInterface` table: `FindClass`, `GetMethodID`, `NewObjectA`,
`CallObjectMethod*`, `NewStringUTF`, `GetByteArrayRegion`, …).

---

## 3. Reconstructed flow

```
Java  Signer.sign(params)
  |- d3.a(...)                      -> canonical string
  |- o3.a(a0)                       -> adj_verification  (XOR 19-byte key, offline-able)
  |- NativeLibHelper.nSign(ctx, LinkedHashMap, byte[], int)
  |     native: anti-tamper sweep + JNI reflection
  |       KeyStore.getInstance("AndroidKeyStore"); load(null)
  |       key = ks.getKey("key2", null)                 // TEE handle, no raw bytes
  |       Mac m = Mac.getInstance("HmacSHA256"); m.init(key)
  |       m.update(canonical.getBytes()); mac = m.doFinal()
  |       -> returns 192 bytes
  |- u2.a(map, blob)                -> "Signature signature=<b64(192B)>, adj_signing_id=..., ..."
```

Observed live (09-09 capture, `activity_kind=event`):
`signature == Base64(nSign output)`, `len = 192`.

Note: HMAC-SHA256 is **32 bytes**, the blob is **192** — the returned value is an
envelope, not a bare MAC. Its layout is not determined by this static pass.

### Fallback path (present, not taken on this device)

`SecretKeySpec([B, String)` + `RSA/ECB/PKCS1Padding` + `adjust_keys`/`encrypted_key`
SharedPreferences + `AES` are all in the table: if AndroidKeyStore is unavailable the
SDK can generate a raw key, wrap it, and persist the wrapped blob. On this app/device
that branch is not used — `adjust_preferences.xml` holds only `install_tracked` and
`push_token`; there is no `adjust_keys` pref.

---

## 4. Why this closes offline signing

* To verify an HMAC, the verifier must hold the same key. Adjust's server verifies, so
  **Adjust holds `key2`**. A self-chosen key cannot produce a MAC the server accepts —
  it would compute a different value.
* `key2` here is an AndroidKeyStore entry on a device whose app `minSdk = 29`, i.e.
  always TEE/StrongBox-backed and non-exportable; `KeyInfo.isInsideSecureHardware()`
  is literally among the reflected methods, so the SDK checks this.
* No raw key bytes exist anywhere in the APK, in the `.so`, or in app private storage.

---

## 5. Open question + the decisive experiment

**What are the 192 bytes?** Static analysis cannot settle it (the value is produced
inside the flattened dispatcher). The cheap, decisive experiment is to extend the
existing LSPosed module to hook the JCA itself:

* `javax.crypto.Mac.init/update/doFinal` → algorithm, input length, **MAC length**
* `javax.crypto.Cipher.init/doFinal` → transformation, in/out lengths
* `java.security.KeyStore.getEntry/getKey` → alias, and whether it is a keystore key
* `SecretKeySpec.<init>` → whether the raw-key fallback ever fires

That tells us the envelope layout (how many of the 192 bytes are the MAC, and what the
rest is) without guessing, and it needs no frida.

---

## 6. Tooling produced

| file | purpose |
|---|---|
| `adj9/rev/elf.py` | minimal ELF64/aarch64 reader: sections, dynsym, PLT→import map |
| `adj9/rev/strings.py` | first-pass `.data` decoder |
| `adj9/rev/strings2.py` | DP decoder for the `[cipher+NUL]` framing |
| `adj9/rev/datarefs.py` | bit-pattern ADRP/ADD + BL scan over all of `.text` |
| `adj9/rev/decryptors.py` | harvests in-place decrypt blocks (`movi` key + `ldr/str`) |
| `adj9/rev/decode_exact.py` | decodes each string with the key from its `movi` |
| `adj9/rev/callgraph.py` | capstone call-graph + `JNINativeInterface` offset table |
| `adj9/rev/nsign_map.py` | nSign call graph with decrypt-site attribution |
| `adj9/rev/cfg.py` | branch-following CFG crawl from `nSign` |
| `adj9/rev/strings_final.pkl` | 511 decoded strings (va → key, len, text) |
| `adj9/rev/nsign_cfg.pkl` | reachable instruction set from `nSign` |
