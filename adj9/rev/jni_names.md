---
title: jni_names
---

# JNI name/sig blobs of the region path — DECODED (libsigner.so, arm64)

Date: 2026-09-23. Follow-up to `writer_findings.md` (slice 141 + Java-side extraction).
Library: `extracted/arm64/lib/arm64-v8a/libsigner.so`. Tools used here: `pass_scan.py`,
`pass_scan2.py`, `data_refs.log` (adr/adrp+add sweep), `emu_be168.py` (Unicorn emulation
of `sub_be168` / `sub_8d6f4` with a stubbed JNIEnv), corrected table `blob_table_true.log`.

## 0. CRITICAL CORRECTION — the old .data VAs were shifted by 0x1E0

Every .data VA in `writer_findings.md`, `blob_table.log` and `decode_blobs*.py` is
**0x1E0 too low**. The old scripts used `file_off = VA - 0x7E20`; the program headers
say the RW segments map at **`file_off = VA - 0x8000`** (PT_LOAD: off 0x148e60→va
0x14ce60, off 0x149c20→va 0x151c20; `.data` = va 0x151c20..0x15522a, `.bss` to
0x155e70). Verified with an anchor: the plaintext SHA-256 hex constant
(`b1c22b0c…faa16`) is referenced by code at 0x97a4c/0x97fa8/0x999ac/0x99a0c as
`adr → 0x1536d0`, and `0x1536d0 - 0x8000 = file 0x14b6d0` where the constant sits
(old labels called it "0x1534f0").

So: **true_VA = old_label + 0x1E0**, and `file_off = true_VA - 0x8000`.
Code VAs (0x8d6f4, 0xbe168, …) were always correct. The corrected self-describing
table decode (473 printable entries) is in `blob_table_true.log`.

Table format (unchanged, one key per entry):
`[data ^ key][key][zero pad to 4-byte alignment]`. Adjacent short entries may share no
zero run (e.g. `…Exception\0` immediately followed by `I\0`), which is why the old
sliding parser missed/merged them. Each entry has exactly ONE decryptor — an in-place
`ldr d/q; eor v0, vN; str` + `ldrb/eor w/strb` block whose immediate/movi key EQUALS the
stored key byte — living in the consumer function, flag-guarded (`strb #1,[0x1550xxx]`,
CAS via 0x1483e0, cleared by `stlrb wzr` before re-use). The "multi-pass" impression in
the old findings was entirely an artifact of the shifted mapping.

## 1. THE ANSWER — the int fields read at 0xbe604

`sub_be168` (0xbe168) is the JNI fetcher. Its int path, **verified end-to-end by
emulation** (fake JNIEnv, real library code, `emu_be168.py`):

```
0xbe6a4/0xbe6a8  GetObjectClass(env, obj)            ; clazz = runtime class of the object
                                                     ; handed down from nSign's payload
0xbe484/0xbe49c  GetFieldID(env, clazz, name, sig)   ; name  = 0x153690 OR 0x1536a0 (per call)
                                                     ; sig   = 0x1540d4
0xbe5f4/0xbe5f8  GetIntField(env, obj, fid)          ; slot 0x320
0xbe5fc/0xbe604  ldr x8,[sp,#0x20]; str w0,[x8]      ; *(&ctx+0x60) / *(&ctx+0x64) = value
0xbe814          DeleteLocalRef(env, clazz)
```

Emulated trace (call #1): `GetObjectClass → GetFieldID(name@0x153690, sig@0x1540d4) →
GetIntField → *x4 = value → DeleteLocalRef`, return 0. Call #2 identical with
name@0x1536a0. Emulation source: `emu_be168.py`.

### The exact strings (raw bytes, key, decryptor site)

| blob VA | raw bytes (file 0x…-0x8000) | key | decryptor site | plaintext |
|---|---|---|---|---|
| **0x153690** | `2f 31 3c 2c 30 08 31 20 3d 34 2b 58` (12B) | 0x58 (key byte @0x15369c) | 0x9086c in sub_8d6f4 (`adr x0,#0x153690; movi v1.8b,#0x58; ldr d0/eor/str` + ldrb #8..#b) | **`widthPixels`** |
| **0x1536a0** | `82 8f 83 8d 82 9e ba 83 92 8f 86 99 ea` (13B) | 0xea (@0x1536ad) | 0x90d64 in sub_8d6f4 | **`heightPixels`** |
| **0x1540d4** | `6b 22` (1B + NUL) | 0x22 (@0x1540d5) | 0xbe770 in sub_be168 (`adr x17,#0x1540d4; eor w,#0x22222222` ×2) | **`I`** |

- Call #1: `adr x3,#0x153690` @ **0x912a4** → `bl 0xbe168` @ **0x912d0** → int stored at
  **ctx+0x60** (region dword #2, B+0x60).
- Call #2: `adr x3,#0x1536a0` @ **0x937e8** → `bl 0xbe168` @ **0x93814** → int stored at
  **ctx+0x64** (B+0x64).
- Both GetFieldID calls share the sig blob 0x1540d4 = `I` — an exact int signature,
  consistent with slot 0x320 = GetIntField.

**Class:** `GetObjectClass(env, obj)` — the runtime class of the object threaded from
`nSign` → 0x95fc4 → VM → sub_8d6f4 → sub_be168. `widthPixels`/`heightPixels` are the
canonical **android.util.DisplayMetrics** int fields, and the surrounding code confirms
that type: `FindClass("android/util/DisplayMetrics")` (name blob 0x154290, key 0x55;
slot 0x30 verified at 0xc495c), `GetMethodID(clazz, "getMetrics",
"(Landroid/util/DisplayMetrics;)V")` (0xc3fa8/0xc3fb0, blobs 0x154248 key 0x18 /
0x154260 key 0x68), and `GetMethodID(clazz, "getDisplayMetrics",
"()Landroid/util/DisplayMetrics;")` (0xc90e0/0xc90e8, slot 0x108; blobs 0x154440 key
0xe7 / 0x154460 key 0xc4). So: **the ints are `DisplayMetrics.widthPixels` and
`DisplayMetrics.heightPixels`, read on the runtime class of the passed object via
GetObjectClass.**

## 2. Every other string the region path reads (name+sig+call site)

### sub_be168, string field + package-name path (states verified in the same function;
decryptors verified; this path did not trigger under the stubbed-JNI emulation of the
two int calls — it serves String-field fetches used by other call shapes)

| call | VA | slot | name blob | sig blob |
|---|---|---|---|---|
| GetObjectClass | 0xbeda4 | 0xf8 | — | — |
| GetFieldID | 0xbef68/0xbef80 | 0x2f0 | [sp+8] (= caller's x3) | 0x1540e0 = **`Ljava/lang/String;`** (18B, key 0x8b @0x1540f2, decryptor 0xbec8c) |
| GetObjectField | 0xbeeb0 | 0x2f8 | fid above → result stored to *x4 | — |
| GetMethodID | 0xbf6a8/0xbf6c8 | 0x108 | 0x1540f8 = **`getPackageName`** (15B, key 0x95 @0x154107, decryptor 0xbf8b8) | 0x153950 = **`()Ljava/lang/String;`** (21B, key 0x12 @0x153965, decryptor 0xbf98c) |
| CallObjectMethod | 0xbf588 | 0x110 | mid above | — |
| DeleteLocalRef | 0xbe814 / 0xbf05c / 0xbf7d8 | 0xb8 | — | — |

`java/lang/Exception` (19B, key 0x43 @0x1540d3, decryptor 0xbdeac/0xbe088 in sub_be168)
sits directly before the `I` blob — the exception guard for the same function.

### Cert-fetcher pairs (PackageInfo signature material for #9 / SHA-1)

| GetFieldID site | name blob | sig blob |
|---|---|---|
| 0xc55c4/0xc55cc (slot 0x2f0) | 0x1542b0 = **`signatures`** (10B, key 0xdc, decryptor 0xc56ac) | 0x1542c0 = **`[Landroid/content/pm/Signature;`** (31B, key 0x13) |
| 0xc5d98/0xc5da0 (slot 0x2f0 verified @0xc5db8) | 0x1542e0 = **`signingInfo`** (11B, key 0x4f, decryptor 0xc6018) | 0x1542f0 = **`Landroid/content/pm/SigningInfo;`** (32B, key 0x42) |

Related, in the same 0xc5xxx-0xc8xxx cert/keystore region (true VAs): `getApkContentsSigners`
0x154550 (key 0xf0) with `()[Landroid/content/pm/Signature;` 0x154571 (key 0x25);
`getSigningCertificateHistory` 0x1545a1 (key 0x18); `hasMultipleSigners` 0x1545c0 (key 0x69).

### Engine/bridge strings feeding the tiles (true VAs, old label +0x1E0)

`com.adjust.sdk.sig.Signer::sign\0AdjustSigner` 0x151c50 (key 0xd0), `client_sdk`
0x151c20 (0xbd), `secret_id` 0x151ca0 (0xce), `java.security.NoSuchAlgorithmException`
0x153720 (0x36), `RSA` 0x153794 (0xb5), `decode` 0x1537b4 (0x7d), `javax/crypto/Cipher`
0x1537f0 (0x52), `init` 0x15384c (0xd2), `toString` 0x153937 (0x70), `getBytes`
0x153968 (0xc7), `android/security/keystore/KeyGenParameterSpec$Builder` 0x153980
(0xff), `setAttestationChallenge` + `([B)L…Builder;` 0x1539bf-0x153a7b, `getPrivate`
0x153c41 (0x1d), `java/security/KeyFactory` 0x153c70 (0x0f), `android/security/keystore/
KeyInfo` 0x153d40 (0xd4), `getSecurityLevel` 0x153d70 (0x8b), `getCertificateChain`
0x153db0 (0xeb), `java/security/KeyStore` 0x153e10 (0xf4), `RSA/ECB/PKCS1Padding`
0x154831 (0x11), `adjust_keys` 0x154848 (0x59), `AES` 0x154868 (0x40), `HmacSHA256`
tail of 0x154790 entry (0xcd), `TracerPid:` 0x154939 (0x95). The 64-hex SHA-256
constant sits at **0x1536d0** (plaintext).

## 3. Direct answers to the task questions

1. **Exact NAME of the Java int field read at 0xbe604:** two fields, one per sub_be168
   invocation — **`widthPixels`** (blob 0x153690 ^0x58, call from 0x912a4/0x912d0,
   result → ctx+0x60) and **`heightPixels`** (blob 0x1536a0 ^0xea, call from
   0x937e8/0x93814, result → ctx+0x64).
2. **On which class:** on the runtime class (GetObjectClass @0xbe6a8) of the object
   passed down from nSign — an **android.util.DisplayMetrics** instance (its canonical
   int fields; FindClass/getMetrics/getDisplayMetrics strings around the path confirm
   the type).
3. **Signature:** exactly `I` (blob 0x1540d4 ^0x22) for both.
4. **Other fields/methods on the region path:** String field via GetFieldID sig
   `Ljava/lang/String;` (0x1540e0), `getPackageName` / `()Ljava/lang/String;`
   (0x1540f8 / 0x153950, GetMethodID @0xbf6c8, CallObjectMethod @0xbf588);
   cert fetchers `signatures` / `[Landroid/content/pm/Signature;` (0xc55c4),
   `signingInfo` / `Landroid/content/pm/SigningInfo;` (0xc5d98),
   `getApkContentsSigners`, `getSigningCertificateHistory`, `hasMultipleSigners`;
   metrics glue `getMetrics` / `(Landroid/util/DisplayMetrics;)V`,
   `getDisplayMetrics` / `()Landroid/util/DisplayMetrics;`;
   plus the `getBytes` bridge (0x153968) the worker/engine uses to move Java strings
   to bytes.

## 4. Reproduction

- `python blob_table_true.py`-equivalent: rerun the self-describing parse with
  `DELTA = 0x8000`, `LO = 0x151c20`, `HI = 0x155230` → `blob_table_true.log` (473 entries).
- `python pass_scan2.py` — enumerates decryptor blocks (adr/adrp+add → ldr → eor → str).
- `python emu_be168.py 0x153690` — emulate sub_be168 directly (int path trace).
- `python emu_be168.py 0x153690 fn8d6f4` — emulate sub_8d6f4; shows the 13
  `__system_property_get` probes with fully decrypted names (ro.product.manufacturer,
  ro.product.model, ro.build.fingerprint, …) before the region fill.
