# FINDINGS — creditsea (Adjust SDK 5.8.0) vs penti (Adjust SDK 5.7.0) signer-input diff

Date: 2026-09-29. Workspace: `adj9/rev/creditsea/sdk_diff/`.
Method: dex string-pool parse (`dex_strings.py`), full androguard disassembly of every
`com/adjust/sdk/**` class in both apps (`all_57/`, `all_58/`, 380 vs 311 classes),
register-normalized per-class diffs (`diffs/`), raw byte searches of all dexes and of
`libsigner.so`, plus reuse of the prior native reversing (`adj9/rev/writer_findings.md`)
and `adj9/rev/cert_verify.py`.

Every claim below is labelled PROVEN (directly evidenced from the artifacts listed) or
INFERRED (stated reasoning, not directly observed).

---

## 0. Inputs

| | penti | creditsea |
|---|---|---|
| APK | `extracted/_ref/base.apk` (8 dexes) + `extracted/arm64/lib/arm64-v8a/libsigner.so` | `creditsea_base.apk` (5 dexes) + `C:/Users/Apps/Documents/adjust_Apps/com.creditsea.app/split_config.arm64_v8a.apk` |
| Adjust SDK version string | `5.7.0` (also `android5.7.0` client_sdk) | `5.8.0` (also `android5.8.0` client_sdk) — **PROVEN** |
| sig package | `com/adjust/sdk/sig/**` 125 classes in classes3.dex | same 125 class names in classes.dex (single SDK copy; classes3/4/5 define 0 adjust classes) — **PROVEN** |
| libsigner.so | sha256 `55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc` | **identical** (same sha256, 1,366,632 B) — **PROVEN** (`libs/`) |

creditsea is a Flutter app; the adjust Flutter plugin bridge (`com/adjust/sdk/flutter/AdjustSdk`)
is compiled into the same dex as the native SDK. It does not override `client_sdk`
(no such string); the flutter plugin passes a plain referrer/`tryInstallReferrer` bridge.

---

## 1. (a) New / removed parameter keys, 5.8.0 vs 5.7.0

**PROVEN: NO claims key was added or removed.** Evidence:

1. Whole-dex const-string scans (incl. `const-string/jumbo`) in both apps show every one
   of the 33 law keys (`adj_verification … package_name`, `initiating_package_name`,
   `session_count/store_name_from_system/tracking_enabled/updated_at`, `activity_kind/
   client_sdk/headers_id/native_version`, `adj_signing_id`) referenced by the **same
   classes in both versions**: the profile/tail keys by `Lcom/adjust/sdk/PackageBuilder;`,
   the pinned block by `Lcom/adjust/sdk/sig/u2;`.
2. Per-method key diff of `PackageBuilder` (the only class that builds request params):
   `REMOVED = []`; the only NEW strings are 4 conditional feature-flag keys and log lines
   (below). Full click-parameter vocabulary (`getClickParameters`, ~70 keys) extracted and
   compared — no key diff.
3. Register-normalized diff of all 253 common named adjust classes: 57 changed; every one
   of the changes is R8/obfuscation noise (renamed stdlib helpers `Ld;`→`LB2/a;`,
   `access$NNN` bridge renames, throw-style inlining, `FirstSessionDelayManager`→`P`,
   `reloadPlayIds`→`reloadGoogleAdId`, `reloadNonPlayIds`→`readAndroidId`,
   `const-string`→`const-string/jumbo`, register renumbering) EXCEPT the items listed in
   §3. `Lcom/adjust/sdk/sig/u2;` (claims assembler) and `sig/NativeLibHelper` are
   logic-identical.

**Conditionally new parameter keys in 5.8.0** (PROVEN present in code, INFERRED absent at
runtime): `injectFeatureFlagsWithParameters` (exists in 5.7.0 too) adds, only when the app
calls the corresponding new 5.8.0 disable APIs:

- `ff_gps_adid_disabled` (new in 5.8.0)
- `ff_android_id_disabled` (new in 5.8.0)
- `ff_fire_adid_disabled` (new in 5.8.0)
- `ff_plugins_device_ids_disabled` (new in 5.8.0)

These fire only if `AdjustConfig.disableGoogleAdIdReading()/disableAndroidIdReading()/
disableFireAdIdReading()/disableDeviceIdsFromPluginsReading()` are called. Nothing in
creditsea's adjust classes calls them, and no adjust class references them outside
`PackageBuilder`; the Flutter plugin bridge does not either (method list checked).
Confidence they never appear in creditsea requests: high (INFERRED).

Non-key SDK deltas that do NOT touch claims (PROVEN present, INFERRED dormant):
Meta install referrer package (`com/adjust/sdk/meta/*`, reads
`com.facebook.katana|lite.provider.InstallReferrerProvider`,
`com.instagram.contentprovider.InstallReferrerProvider`; wired through AsyncTask
`Lcom/adjust/sdk/J;` but the only internal caller is `AdjustMetaReferrer.getMetaInstallReferrer`
— i.e. the public API `AdjustMetaReferrer.readMetaReferrer(context)`; no internal
SDK caller and no caller in any creditsea dex → dormant), and Samsung preinstall
(`content_provider_samsung_maps`, `com.samsung.android.mapsagent.providers.apptracking`,
`PreinstallUtil.getPayloadFromContentProviderSamsungMaps` — feeds a preinstall
`sdk_click`, not the session claims).

---

## 2. (b) Predicted 5.8.0 claims key order

**PROVEN (as far as statics go): identical to the proven 5.7.0 law** — i.e.
`desc10_law.desc10_keys(kind)` applies unchanged. The serialization order is produced by
the sig package (claims map `LinkedHashMap` → `u2.a()` → `NativeLibHelper.nSign(Context,
LinkedHashMap, byte[], int)`), and the entire `com/adjust/sdk/sig/**` package plus the
`ActivityPackageSender` signing trigger are instruction-identical after register
normalization. No new sorted-in key exists unconditionally.

`predicted_desc10_58.py` in this directory implements `build_desc10` for 5.8.0: it is the
5.7.0 law re-exported with the version-value caveat (`client_sdk` = `android5.8.0`) and the
conditional `ff_*` warning. Confidence: high; one real device signing from creditsea is
the only way to upgrade it to byte-proof.

---

## 3. (c) D8 (descriptor #8)

**PROVEN: D8 is NOT built by Java in either version.** The 16-byte value
`bffffffffffffd1f0007000000000000` appears NOWHERE in the 13 penti dexes or 5 creditsea
dexes — not as a fill-array-data payload (`bf ff ff ff ff ff ff fd 1f 00 07 ...`), not as
const-wide/const-wide-high operands (any endianness split tried), not XOR'd with the
observed keys. `u2`'s signing path passes `(Context, LinkedHashMap claims, byte[] keystore
material, SDK_INT)` to `NativeLibHelper.nSign` — descriptor construction is entirely
native.

**PROVEN: same builder in both apps.** `libsigner.so` is byte-identical (§0). Prior
reversing (`adj9/rev/writer_findings.md` §4, worker_95fc4/sub_95fc4 dumps) classifies
descriptor #8 (ctx+0x134) as a **static XOR-keyed constant stored in .data
(0x152xxx/0x1540d4 family), deobfuscated in place** — "not random, not request-hashed".

**CONCLUSION: D8 = SAME for creditsea.** Identical .so + static-table mechanism + the
slice-131/99 proof that #8 is constant across all 10 penti signings (different claims,
seconds, days). D8 is NOT the cause of the unverifiable signature. (Residual caveat,
INFERRED-high: if the blob's XOR key were itself app-derived, the identical .so could
still yield different output — but the prior classification states the keys are static
constants, and penti's #8 never varied while app-derived descriptors do.)

---

## 4. (d) Other app-side signer-input differences — THE ROOT CAUSE LIVES HERE

Descriptor provenance from the prior native reversing (writer_findings.md §4, all
**PROVEN** for the penti build, same .so here):

| desc | source | 5.7.0 vs 5.8.0 | penti vs creditsea |
|---|---|---|---|
| #7 | unpadded claims length | same law | follows from claims (same law) |
| #8 | static XOR-keyed constant in .data | unchanged | **SAME** |
| #9 | **SHA-1 of the APK signing certificate** (JNI `signatures`/`getSigningCertificateHistory`) | unchanged code | **DIFFERENT** — see below |
| #10 | claims (desc10 law) | same law | values differ per app (expected) |
| #2 | JNI GetStaticIntField of sig-SDK static int fields | sig code identical | same |
| #0/#4 | keyed-XOR tiles over ctx fields + claims len + **SHA-1 material** | unchanged code | **INFERRED different** (cert hash feeds the material) |

**The app signing certificates differ (PROVEN via `adj9/rev/cert_verify.py`, v2 signing
block):**

- penti: 745-B cert, SHA-1 `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` == descriptor #9
  (also confirmed by the on-device runtime JCA trace, `APK_CERT_RESULT.md`).
- creditsea: 1421-B cert, SHA-1 **`06f5ffcee0541608765407ab9e0180e7b1b7e7d0`**.

`adj9/adj9_tool/adj9_signer.py` hardcodes `D9_HEX = "fad0f10d…74bd"` (#9: APK cert SHA-1)
and `D8_HEX` (fine). Any creditsea blob minted with penti's #9 carries the wrong app's
certificate fingerprint inside the signed descriptor set — the server cannot verify it.
Because the #0/#4 tiles also consume SHA-1 material, they inherit the same problem.

Other checked-and-cleared items (PROVEN):
- Pinned constants `adj_signing_id '1500000'`, `headers_id '10'`, `native_version '5.0.0'`
  do not appear as literals in either app's dexes (native-injected, as expected). The
  standalone `5.0.7` string in creditsea's classes3.dex is **Firebase Crashlytics**
  (`FlutterFirebaseAppRegistrar.getComponents`), NOT an Adjust native_version. No
  `1500001`/`5.0.1`-style new sig values exist in either dex.
- `adj_signing_id`/`headers_id`/`algorithm`/`native_version`/`adj_verification` are read
  by `u2` identically in both versions; the `Signature` header format string
  (`Signature %s,%s,%s,%s,%s,%s`) is identical.
- 5.7.0-only `readObject` bug in `ActivityPackage` (`"errorCount"` vs serial field
  `"retryCount"`) was fixed in 5.8.0 — irrelevant to signing.

---

## 5. referrer transport + no_sdkclick (coordinator add-on)

1. **Play install referrer transport — PROVEN unchanged.** 5.8.0 still builds a separate
   sdk_click ActivityPackage: `PackageFactory.buildInstallReferrerSdkClickPackage` exists
   with the same body (signature only renamed `FirstSessionDelayManager`→`P`),
   `SdkClickHandler.sendSdkClickI` and its `sdk_click` path are logic-identical; the
   strings `install_referrer`, `referrer`, `referrer_api` are referenced by the same
   classes (`PackageBuilder`, `PackageFactory`, `SdkClickHandler`) in both versions.
   The click-package keys (`raw_referrer`, `referrer_api`, `click_time`,
   `install_begin_time`, `google_play_instant`, `is_click`, …) are identical.
2. **`no_sdkclick` — PROVEN absent.** The literal `no_sdkclick` appears in NO dex of
   EITHER app (all 13 + 5 dexes byte-searched) and no code reads or handles it. The
   `adjust_no_sdkclick=1` response flag is therefore purely server-side for this SDK
   generation; nothing in the client changes behavior on it.
3. **Session parameter keys — PROVEN identical.** `PackageBuilder.buildSessionPackage`
   keys are the same set in both versions (see §1); the only conditional additions are
   the four new `ff_*` flags (§1), which require opt-in disable calls.
4. **New referrer sources in 5.8.0** (both PROVEN present, INFERRED dormant in creditsea):
   the Meta install referrer (Facebook/Instagram content providers) and Samsung preinstall
   (Maps agent content provider). Neither is invoked from inside the SDK's own flow in
   creditsea's build (no internal caller for `AdjustMetaReferrer.readMetaReferrer`; Samsung
   preinstall only feeds `buildPreinstallSdkClickPackage` when preinstall tracking is
   enabled and the provider resolves). If either ever fires, its payload enters through
   the SAME sdk_click path (a `ReferrerDetails`), not through the session package.

---

## 6. Verdict (single most likely cause)

**The claims law and D8 transfer to 5.8.0 unchanged — the unverifiable signature is
almost certainly the APP-SPECIFIC descriptors: #9 is the APK signing-certificate SHA-1
(penti `fad0f10d…` vs creditsea `06f5ffcee0541608765407ab9e0180e7b1b7e7d0`), and the
#0/#4 tiles consume SHA-1 material.** A creditsea request signed with any penti-derived
constant set (notably the hardcoded `D9_HEX` in `adj9/adj9_tool/adj9_signer.py`) presents
the wrong app identity inside the signed blob and cannot verify. Fix: derive #9 (and the
#0/#4 SHA-1 inputs) from creditsea's own certificate, keeping the proven 5.7.0 claims law
and D8 as-is.

## Artifacts in this directory

- `penti_dex/`, `creditsea_dex/` — extracted classes*.dex (8 + 5).
- `strings_57_all.txt`, `strings_58_all.txt` — full dex string pools (426,982 / 143,353).
- `diff_strings_58.txt`, `diff_strings_57.txt` — raw app-wide string-set diffs
  (68,465 new / 339,509 gone; dominated by creditsea's Flutter/Firebase stack).
- `diff_adjust_58.txt`, `diff_adjust_57.txt` — adjust-SDK-scoped string diffs.
- `all_57/`, `all_58/` — full instruction dumps of every com/adjust/sdk class.
- `classes_57/`, `classes_58/`, `diffs/` — per-class dumps and normalized diffs.
- `libs/` — both libsigner.so copies (sha256-identical).
- `predicted_desc10_58.py` — 5.8.0 desc10 builder (identical law).
- `dex_strings.py`, `analyze_dex.py` — tooling.
