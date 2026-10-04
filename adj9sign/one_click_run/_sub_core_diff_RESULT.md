# _sub_core_diff_RESULT.md — iOS vs Android adj9 core static cross-diff (v5.0.0)

Date: 2026-10-01. Scope: authorized security research, public GitHub release
binaries + local static analysis only.

## 0. Artifacts produced

Binaries (downloaded, github.com/adjust/adjust_signature_sdk tag v5.0.0,
`C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins/`):

| file | size | sha256 |
|---|---|---|
| adjust-android-signature-5.0.0.aar | 2201424 | 29f3dc05567227d2fc2de388a149e6be055a1f13bb1ac1f6a1ab212b6a8b38f6 |
| AdjustSigSdk-iOS-tvOS-Dynamic-5.0.0.xcframework.zip | 4049357 | 0075b150fdfe792aedab182c4f4b3bdfe6ce89d61b016e15606ef9bd5c2a35d1 |
| AdjustSigSdk-iOS-Static-5.0.0.a.zip | 902298 | f0e6717810035e10e26387b35b8c7a82d4979fe621f5dce5236dcdb6738f618b |

Extracted under `core_bins/extracted/`: AAR (4 ABIs + classes.jar), dynamic
xcframework (ios-arm64 device 1942440 B; ios-arm64_x86_64-simulator arm64
slice 2073312 B; tvOS and maccatalyst slices present), static `AdjustSigSdk.a`
(4161696 B, fat archive).

Scripts (all in `adj9sign/one_click_run/`, none of the existing files touched):
`_sub_core_fetch.py`, `_sub_core_macho.py`, `_sub_core_constscan.py`
(+`_out.json`), `_sub_core_kbhunt.py` (+`_out.json`), `_sub_core_strdiff.py`
(+`_out.json`), `_sub_core_strdeob.py`, `_sub_core_claimkeys.py`,
`_sub_core_fulldata.py`, `_sub_core_allstrings.py`, `_sub_core_order.py`
(+`_strings.json`), `_sub_core_refs.py` (+`_out.json`),
`_sub_core_disasm.py`, `_sub_core_clusters.py`.

## 1. Android reference identity (evidence-backed)

The AAR's `jni/arm64-v8a/libsigner.so` is sha256
`55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc`,
byte-identical to the locally reversed reference (`adj9/rev/creditsea/
libsigner.so`, `extracted/arm64/lib/arm64-v8a/libsigner.so`, and
`extracted/_ref/sig500.aar.so`). **The official v5.0.0 release native IS the
lib the team's Android law was proven on.** Positive control for every scan
below is therefore exact.

## 2. Constants cross-scan (task 3a)

Storage law in both natives (no secret appears as a contiguous blob):
movz/movk immediates, XOR-masked. Scan = raw bytes, raw LE dwords, and
arm64 movz/movk immediate-stream reconstruction
(`_sub_core_constscan.py`, control = Android .so):

| constant | Android .so (control) | iOS device arm64 | iOS sim arm64 |
|---|---|---|---|
| DK (digest MAC key, plain dwords) | 8/8 imm (0x1061e4..) | **8/8 imm** (0x1ab054..) | 8/8 imm |
| IV2 (XOR 0xCCCCCCCC dwords) | 8/8 imm | **8/8 imm** | 8/8 imm |
| SHA-256 IV (XOR 0xCC, 2 copies) | 8/8, 16 hits | **8/8, 16 hits** | 8/8, 16 hits |
| SHA-256 K[0..7] (XOR 0xAA, 2 copies) | 8/8, 16 hits | **8/8, 16 hits** | 8/8, 16 hits |
| KB round keys (240 B) | 481-site VM push block | **481-site push block, values = Android KB XOR 0x55 (240/240)** | same (sim 0x1c4840) |
| AES S-box raw table | absent (generated) | absent (generated) | absent |
| sha256("") raw | absent | absent | absent |
| any DK/IV2/SHA-IV as raw bytes or raw LE dwords | absent | absent | absent (static .a x86 member shows DK dwords raw LE, as expected for x86 immediates) |

KB extraction detail (evidence-backed): a single 481-site run at iOS
0x1a4a64 (device) with slot offsets 257..496 consecutive and final count
240 — the exact structure of Android's KB push block (derive_kb law); the
value immediates satisfy `imm ^ AndroidKB[i] == 0x55` for **all 240 bytes**
(single constant mask; probability of coincidence ~0). I.e. the iOS core
carries the SAME whitening round-key schedule, stored XOR-0x55-whitened
(Android pushes it plain in its VM program image). Four `movz w,#0x55`
mask loads exist in the iOS binary (0x1b16d8, 0x1b186c, 0x1b7df4,
0x1b8198).

**Verdict: the Android-proven composition (KB-whitening SPN + sha256-IV2
BLOCK + double-padded sha256(K) digest) is byte-present in the iOS core.
The cipher is the same; only per-string obfuscation differs.**

## 3. iOS claim-key vocabulary (task 3b)

The iOS core stores its strings XOR-obfuscated (per-string key byte =
encoded terminator byte; several strings are double-XORed). Fully decoded
from `__DATA,__data` (`_sub_core_allstrings.py`, `_sub_core_order.py`):

Bridge keys (match open SDK v5.8.0 `ADJRequestHandler.signWithSigPlugin…`
exactly — extraParams in: `client_sdk`, `activity_kind`, `endpoint`,
`control_params` (loop-copied server keys); outputParams out:
`authorization`, `endpoint`):

- 0x1d60a0 `client_sdk` (k=0x5A), 0x1d6090 `activity_kind` (k=0xDB),
  0x1d6140 `endpoint` (k=0xA3), 0x1d6118 `authorization` (k=0xD3),
  0x1d6048 `environment` (k=0x83; CFString literal `"sandbox"` also in
  `__cstring`)

Core-internal claim keys (iOS-only, never on Android):

- 0x1d60b0 `adj_signing_id` (k=0x2A), 0x1d60c0 `signature` (k=0x9D),
  0x1d60d0 `headers_id` (k=0xD3), 0x1d60e0 `native_version` (k=0x05),
  0x1d60f0 `algorithm` (k=0x91), 0x1d6100 `adj_verification` (k=0x40),
  0x1d6130 `network_payload` (k=0x48), 0x1d6a28 `bundle_id` (k=0xF8),
  0x1d6a32 `idfv` (k=0x0C), 0x1d6a38 `app_version` (k=0xD9),
  0x1d6a50 `app_version_short` (k=0x1E), 0x1d6a68 `os_name` (k=0x40),
  0x1d6aa8 `secret_id` (k=0x0F)

Claim VALUES found as obfuscated strings: `1500000` (0x1d6ab8, k=0xBE —
the same adj_signing_id value as Android), `adj9` (0x1d6ac3, k=0xAE —
presumably the `algorithm` value), `ios` (0x1d6556, k=0xF8) and
`ios-simulator` (0x1d6a98, k=0xCF) — presumably `os_name` values,
`sandbox` (plain CFString).

Key ORDER: the binary's control flow is flattened (dispatcher at 0x6a370;
per-string in-place de-obfuscation `eor` loops, e.g. mask 0x9D for
`signature` at 0x6ba2c). Static reference clusters (weak evidence, labelled
as such) repeat the sequence `signature → headers_id → adj_signing_id →
native_version → algorithm` at 6+ sites (0x81f2c, 0xcd828, 0x120b18,
0x1387c8, 0x15dc9c, 0x162074, 0x183234), and the dictionary-construction
site 0x6cffc–0x6d13c inserts `adj_signing_id → signature → headers_id →
native_version → algorithm → adj_verification` in one unrolled run
(15-instruction stride, `[dict setObject:.. forKey:<string>]` pattern via
objc stubs). Given flattening, treat these as candidate orders, not proof;
the vocabulary itself is strong.

Device-claims collection cluster 0x176e30..0x179444: `bundle_id → idfv →
app_version → app_version_short → ios-simulator → os_name →
adj_verification`.

## 4. iOS-only data sources (task 3c)

The closed core's own `__objc_methname`/`__cstring` tables prove it pulls,
by itself, what Android never does (all evidence-backed strings):

| selector / string | use (inferred from pairing) |
|---|---|
| `appStoreReceiptURL`, `dataWithContentsOfURL:` | reads the App Store receipt file |
| PKCS#7/CMS OIDs in __data: `1.2.840.113549.1.7.2` (signedData), `1.2.840.113549.1.7.1` (data), `…1.1.1` (rsaEncryption) | the core parses the receipt's PKCS#7 envelope itself |
| `environment` key + plain `sandbox` CFString | receipt/StoreKit environment claim |
| `identifierForVendor` + `currentDevice` | `idfv` claim |
| `getUUIDBytes:` (CFUUID), `UUIDString` | UUID material (headers_id/nonce candidate) |
| `objectForInfoDictionaryKey:`, `CFBundleShortVersionString`, `CFBundleVersion`, `mainBundle` | `app_version` / `app_version_short` claims = host app's Info.plist versions |
| `initWithLocaleIdentifier: en_US_POSIX`, `setDateFormat: yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'`, `setTimeZone: timeZoneForSecondsFromGMT:` (0) | canonical UTC timestamps for claims (NSLocale/NSTimeZone usage) |
| `base64EncodedStringWithOptions:`, `dataWithBytes:length:`, `%s="%@"`, `Signature %@,%@,%@,%@,%@,%@` | blob base64 + outputParams `Signature` header formatting (6 fields) |
| `frida-gadget` (0x1d6ad0), `AgentController`, `ADJRequestHandler`, `signWithSigPlugin`, `sendPackageBy` | anti-tamper / SDK-integrity probe surface (inferred purpose) |
| `/dev/urandom`, `elapsed_time_since_ms`, `util.c`, log tags `VERB/DEBG/WARN/ERRO`, `SDKv5 Signing all the parameters begin/end`, `ad_impression_counts`, `ad_revenue_network`, `ad_verification`, VM assert strings `fidx < CORE_MAX_STATE_COUNT`, `STATE != CORE_RESERVED_STATE`, `core_data_add_state_impl` | internal VM/logging; same FinEx-style VM architecture as Android (push-block targets 1603/302/240 sites mirror Android's 1346/300/240) |

Also present: ~22 obfuscated `simulator_*` preference-key strings
(`simulator_udid`, `simulator_model_identifier`, `simulator_boot_time`,
`simulator_mainscreen_scale`, …) — simulator fingerprinting inputs.

## 5. Strings diff summary (task 3a)

- In Android .so but NOT iOS: JNI symbols
  (`Java_com_adjust_sdk_sig_NativeLibHelper_nSign/nOnResume`), bionic
  linkage strings, `SHA-256` rodata tag, PGO/bolt build tag. No signature
  key/claim strings in plain text on either side (both obfuscate).
- In iOS but NOT Android: everything in sections 3-4 above; the Android
  AAR contains no claim keys at all in the .so (they live in
  classes.jar/SDK Java layer: `classes.jar` extracted alongside,
  `NativeLibHelper` bridge), whereas the iOS core embeds its claim keys
  (XOR-obfuscated) and does its own device collection.

## 6. Delta verdict (task 4)

1. **Cipher identity: CONFIRMED SAME (high confidence, byte-level).**
   KB (240 B, XOR-0x55 storage), IV2 (XOR-0xCC), DK (plain), SHA-256 IV
   (XOR-0xCC x2) and K64 (XOR-0xAA x2) are identical to the Android-proven
   values. There is no iOS-specific key material. A working Android signer
   should be able to produce the iOS record/digest for identical claims.
2. **What the iOS core adds is CLAIMS, not math.** iOS-only claim keys
   absent from the Android law: `signature`, `algorithm`, `adj_verification`,
   `authorization`, `environment`, `network_payload`, `os_name`,
   `bundle_id`, `idfv`, `app_version`, `app_version_short`, `secret_id`.
   Candidate value bindings (inferred unless noted):
   `adj_signing_id` = "1500000" (evidence), `algorithm` = "adj9"
   (evidence of the literal; binding inferred), `os_name` = "ios" /
   "ios-simulator" (evidence of literals; binding inferred),
   `environment` = "sandbox"/"production" (inferred),
   `app_version(_short)` = host Info.plist CFBundleShortVersionString /
   CFBundleVersion (inferred), `idfv` = UIDevice identifierForVendor
   (inferred), `secret_id` = SDK-side value (inferred).
3. **Receipt path is real but likely feeds verification-style claims**
   (`adj_verification`, `signature`): the core downloads/parses the App
   Store receipt (PKCS#7 OIDs present). Evidence of parsing: strong;
   exact claim binding: inferred.
4. **Key order: not statically provable** (control-flow flattening).
   Candidate constant-key sequence `signature, headers_id,
   adj_signing_id, native_version, algorithm` recurs at 6+ sites; the
   Android-law 5 constants (`adj_signing_id, activity_kind, client_sdk,
   headers_id, native_version`) are all present. Recommend confirming
   order against the team's live captures using this vocabulary.
5. **Same VM family.** The iOS core embeds the same FinEx-style unrolled
   push-block VM program (481-site KB block; analogous 302/240-site
   blocks) — the Android reversal's structure carries over.

Confidence labels: section 1-2 and the string decodings = evidence-backed
(reproducible with the scripts); claim-to-source bindings and anti-tamper
purpose = inferred; key order = weak/hint-only.
