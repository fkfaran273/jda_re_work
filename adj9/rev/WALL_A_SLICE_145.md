# SLICE 145 — the region is NOT entropy: JNI bridge to Java state + APK-cert SHA-1 (offline-computable in principle)

Date: 2026-09-22/23. Subagents (3): static RE (`rev/writer_findings.md`),
offline derivation (`rev/deriv3.md`, 87.2M comparisons), device forensics
(`rev/struct_diff/STRUCT_DIFF.md` + `t1_struct.bin`).

## 0. What changed in the model

Slice 140's "per-process init-time heap entropy, not offline-derivable" is
**REFUTED**. The fill path contains **no PRNG and no kernel entropy** — the
region is built from (a) XOR-obfuscated static tables in the .so, (b) the APK's
signing-cert **SHA-1**, and (c) **Java-side state read over JNI** during
signing.

## 1. Writer chain (static, proven)

```
nSign (0xdb1cc, JNI export)
 └ sub_95fc4 (0xdb24c) — spawns worker 0x962ac (Attach/DetachCurrentThread
     wrapper; the "vtables" were the JNI function table all along)
 └ VM interpreter (~0xfb00, dispatcher 0xffc74)
     └ sub_8d6f4 — region builder (zeroed 0x878-B ctx; claims-len at ctx+8)
         └ sub_be168 — JNI value fetches, interleaved with builder sub_9afa4
             0xbe6a8 GetObjectClass → 0xbe49c GetFieldID (XOR-obfuscated
             name/sig) → 0xbe604 `str w0,[x4]`  ⇒ descriptor #2 = a JAVA
             INT FIELD of the Signer object (slot 0x320 = GetIntField,
             corrected from GetStaticIntField).
```

## 2. The string table is fully cracked (770 entries)

.data VA 0x151000–0x15540A is a self-describing XOR table
`[data^key][key][00 00 00]` (file_off = VA−0x7E20). Decoded plaintext includes:
`com.adjust.sdk.sig.Signer` + `sign` + tag `AdjustSigner`, sig `([B)[B`,
`secret_id`, `client_sdk`, `adj9`, `HmacSHA256`, `javax/crypto/Mac`,
Android Keystore (`KeyGenParameterSpec$Builder`, `setAttestationChallenge`,
`setIsStrongBoxBacked`), APK-cert fetchers (`signatures`, `signingInfo`,
`getApkContentsSigners`, `getSigningCertificateHistory`), SharedPreferences
`adjust_keys`, `RSA/ECB/PKCS1Padding`, anti-debug (`TracerPid:`), and a
plaintext 64-hex SHA-256 constant at 0x1534f0.

Consequences:
* **#9 = SHA-1 of the APK signing certificate** (SHA-1 consts at 0x3610–0x364f;
  `fad0f10d…` appears in NO shipped binary — it is computed at runtime).
* **#8** = XOR-table constants (cert/config derived).
* **#0/#4** = keyed-XOR block construction (81 eor sites) over ctx fields +
  Java byte[] material fetched via `getBytes` bridges.
* The 0x40/0xc "engine buffers" (0x153788…) are deobfuscated NAME strings
  (`getBytes`, `android/security/keystore/…`), not payloads.

## 3. Live struct (device)

Captured once (`t1_struct.bin`, B=0x7bd5676d50, pid 26530): struct is
**transient** (exists only during the ~35–100 s-lagged signing flush, freed
after seconds; the live #8 dword order differs from the wire form — three of
four words match, reordered). Per-signing changes (from the prior session's
single-capture diff): created_at region, claims lengths (B+0x154: 0x168/0x5a),
descriptor blob B+0x134..0x154, header word at B+0x00. Constant: #9 SHA-1,
adj_verification, install timestamp, app_token, id-table. No counter behavior
at B+0x64.

## 4. Offline derivation battery: ZERO standard-keyed hits (consistent)

deriv3: 4,036 candidate keys (474 movz/movk constants, 891 entropy runs,
strings+derivatives) × 9 families (AES-ECB, HMAC-MD5/SHA1/SHA256, secret-concat
MD5/SHA256, SipHash-2-4/1-3, XOR-mask, crc32/fnv1a/murmur3 seeded) × 16 rows ×
~25 messages = **87,166,216 comparisons, 0 hits**. libsigner embeds SHA-1
constants ONLY (no AES/MD5/SipHash/murmur/CRC tables). This is CONSISTENT with
§2: the keyed material is Java-side (Keystore/`adjust_keys`/Signer fields), not
a literal in libsigner.so. Nonce probe: S0/S2 differing words look independent
(no PM/LCG/xorshift kinship) — expected if the Java-side material itself
differs per call.

## 5. Environment fix (device) — unblocks frida work

The chronic 1–5 s self-destructs (33 tombstones in `ExoPlayer:Playb`) were the
anti-tamper guard detecting the **LSPosed sslunpinning module scoped to this
app**. Scope row removed (backup: `/data/local/tmp/lsp_bak/`, `tbak.db`,
`tmc.db*`; one-command revert in STRUCT_DIFF.md §8). After soft-reboot the app
ran **40+ min in foreground through login/registration/cart** (pid 925).
Re-apply `setenforce 0` after any reboot. Caveat: live state-file wipes are
overwritten in-memory by the running SDK — cold start required to force
signing; the SDK send pipeline was in post-backoff dormancy at capture time.

## 6. Remaining to full offline mint

1. **Java side** (now cheap: the LSPosed oracle module route is alive again on
   a stable app): dump at signing time the Signer object's int field (#2), the
   byte[] material feeding #0/#4, and the `adjust_keys` SharedPreferences +
   Keystore attestation outputs.
2. **Static**: sub_8d6f4 state-graph walk for the exact fill order of the
   36/8-dword tiles (spill-slot splits are randomized; needs a tag-state
   walker).
3. Then reproduce in Python → py_ladder on a fresh clicked GAID (the slice-144
   negative arm becomes the positive testbed).

## 7. Artifacts

`rev/writer_findings.md` (incl. "Follow-up: Java-side extraction"),
`rev/blob_table.log` + `decode_blobs*.py` (770 decoded strings),
`rev/deriv3.md` + `deriv3.py` + `deriv3_summary.json`,
`rev/struct_diff/STRUCT_DIFF.md` (§8–12) + `t1_struct.bin` + `tSS1..3` +
`struct_candidates.json`, `device/hunt7.sh` (atomic streaming anchor hunter).
