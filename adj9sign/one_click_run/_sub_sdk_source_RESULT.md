# Adjust SDK public-source analysis: how the iOS SDK (v5.8.0) builds the signed parameter map

Sources: `github.com/adjust/ios_sdk` tag **v5.8.0** (matches capture `Client-Sdk: ios5.8.0`; `VERSION` file = `5.8.0`, `Adjust.podspec` s.version = "5.8.0"), `github.com/adjust/android_sdk` tag **v5.8.0**, `github.com/adjust/adjust_signature_sdk` (binary-only), `dev.adjust.com`-linked changelogs. All file paths below are repo-relative to those tags. Local working copies of every quoted file are in `C:/Users/Apps/Downloads/com.penti.app/adj9sign/one_click_run/_scratch_sdk/` (raw downloads from raw.githubusercontent.com).

---

## (a) Where the iOS claims map is built

**Two-layer architecture.** The map is assembled in the OPEN Objective-C SDK layer, then handed to a CLOSED prebuilt native core for the actual signing.

### 1. SDK-layer assembly — `Adjust/Internal/ADJRequestHandler.m` (tag v5.8.0)

Every signed request passes through one function:

- `sendPackageByPOST:sendingParameters:` (lines 75–124) — used for `/session`, `/event`, `/sdk_click`, `/ad_revenue`, `/v2/purchase`, `/verify`, etc. (called from `ADJPackageHandler.m:320` and `ADJSdkClickHandler.m:191`)
- `sendPackageByGET:sendingParameters:` (lines 126–175) — used ONLY for `/attribution` (`ADJAttributionHandler.m:215`)

Both call `signWithSigPluginWithMergedParameters:activityKind:clientSdk:urlHostString:` (lines 582–639), which:

```objc
// line 91-93: claims INPUT map #1
NSMutableDictionary *mergedParameters = [[NSMutableDictionary alloc] initWithDictionary:parameters];  // activityPackage.parameters (deep copy)
[mergedParameters addEntriesFromDictionary:responseData.sendingParameters];

// line 601-619: claims INPUT map #2 ("extraParams")
[extraParams setObject:clientSdk forKey:@"client_sdk"];                                  // e.g. "ios5.8.0"
[extraParams setObject:[ADJActivityKindUtil activityKindToString:activityKind] forKey:@"activity_kind"]; // "session" | "event" | "click" | "attribution" ...
[extraParams setObject:urlHostString forKey:@"endpoint"];                                // e.g. "https://analytics.adjust.com"
NSDictionary *controlParams = [ADJUserDefaults getControlParams];                         // NSUserDefaults key "adj_control_params"
for (key in controlParams) [extraParams setObject:value forKey:key];                     // FLATTENED per-key

// line 627-636: hand both maps to the closed core (via NSInvocation, reflective)
[signerClass respondsToSelector:@selector(sign:withExtraParams:withOutputParams:)];
// -> [ADJSigner sign:mergedParameters withExtraParams:extraParams withOutputParams:outputParams];
```

The signer class `ADJSigner` is resolved by `NSClassFromString(@"ADJSigner")`; if absent, `initSdk:` refuses to start (`Adjust/Adjust.m:362-389`, "Missing signature library, SDK can't be initialised").

### 2. Closed native core — `AdjustSignature/AdjustSigSdk.xcframework`

- Public interface header: `AdjustSignature/AdjustSigSdk.xcframework/ios-arm64/AdjustSigSdk.framework/Headers/ADJSigner.h` (752 bytes):

```objc
+ (nonnull NSString*)getVersion;
+ (void)sign:(nonnull NSMutableDictionary*)packageDict
      withActivityKind:(nonnull const char*)activityKind
        withSdkVersion:(nonnull const char*)sdkVersion;          // v4-era interface (legacy)
+ (void)sign:(nonnull NSDictionary*)packageParamsDict
     withExtraParams:(nonnull NSDictionary*)extraParamsDict
    withOutputParams:(nonnull NSMutableDictionary*)outputParamsDict;   // v5 interface (used)
void _ADJSigner_sign(size_t argc, void** args);                    // C trampoline
```

- The **source is not public**. The distribution repo `github.com/adjust/adjust_signature_sdk` contains only `Package.swift`, `Resources/iOS/PrivacyInfo.xcprivacy`, `VERSION` and LICENSE (org search for other "signature"/"native" repos returns nothing else). Releases ship binaries only: `adjust-android-signature-<v>.aar`, `AdjustSigSdk-iOS-Static-<v>.a.zip`, `AdjustSigSdk-iOS-*-Dynamic/Static-<v>.xcframework.zip`.
- **Version match confirmed**: iOS SDK 5.8.0 changelog ("Version 5.8.0 (6th August 2026) → Updated the Adjust Signature library version to **5.0.0**"; `CHANGELOG.md` line 6). The `adjust_signature_sdk` tag **v5.0.0** exists (`VERSION` = `5.0.0`), and the shipped binary's strings contain the version token `...5.0.0`. So `native_version="5.0.0"` in the capture == the AdjustSigSdk binary in ios_sdk v5.8.0. (5.7.0 shipped signature 3.67.0; older = 3.x series.)

### 3. What happens AFTER signing (critical for wire-vs-claims reconstruction)

`sendPackageByPOST` lines 101–113 / `sendPackageByGET` lines 152–164:

```objc
authorizationHeader = [outputParams objectForKey:@"authorization"];   // -> Authorization header
if ([outputParams objectForKey:@"endpoint"] != nil) urlHostString = ...;  // core can re-route
mergedParameters = outputParams;   // the request body/query is REPLACED by the signer's output
```

then `injectParameters:kvArray:` (lines 521–541) encodes `outputParams` to the wire **skipping exceptionKeys** (lines 64–70):

```
secret_id, signature, headers_id, native_version, algorithm, adj_signing_id
```

**Consequence: the captured wire body is the native core's `outputParams`, NOT the SDK's `mergedParameters`.** Any key the core adds to or drops from `outputParams` (and any exceptionKey it puts there) makes wire ≠ claims-input. The iOS-only presence of `secret_id` and `algorithm` in this wire-strip list is notable — Android does no such filtering.

### 4. What the closed binary visibly contains (public artifact, strings-level)

From `strings` of `AdjustSigSdk.framework/AdjustSigSdk` (ios-arm64, 1.94 MB, ships in the repo):
- Header format string: `Signature %@,%@,%@,%@,%@,%@` — the 6 Authorization components (`signature`, `adj_signing_id`, `algorithm`, `headers_id`, `native_version`, `adj_verification`).
- Crypto: `CC_SHA1/_Final/_Init/_Update`, `CC_SHA224/256/384/512` (claims hashing); `SecKeyVerifySignature` + `SecCertificateCreateWithData` + `SecTrust*` (embedded-cert integrity/self-check).
- The core itself reads: `identifierForVendor` (IDFV), `appStoreReceiptURL`, `bundleIdentifier`, `currentDevice`, main-bundle `Info.plist` keys, `CFUUIDGetUUIDBytes`/`UUIDString` (UUID generation), `base64EncodedStringWithOptions:`.
- All snake_case claim key names (`adj_signing_id`, `headers_id`, ...) are NOT in plaintext — runtime string deobfuscation, so the key list cannot be enumerated from strings.
- Pre-init guard string: "This version of Adjust Signature is not compatible with Adjust SDK v4."

---

## (b) Complete key list with value provenance

### Claims INPUT map #1 — `mergedParameters` = wire package params + sending params

All values are NSString at signing time. Bools encoded `1`/`0` (setBool→setInt); durations `%.2f` then rounded; revenue `%.5f`; epoch dates via `formatSeconds1970` and calendar dates via `formatDate`, both format `yyyy-MM-dd'T'HH:mm:ss.SSS'Z'Z` locale en_US (`ADJUtil.m:43,141-160,201-212`). Dictionary params are JSON-serialized strings (`parameters:setDictionary:forKey:` → `convertDictionaryValues` → `setDictionaryJson`, `ADJPackageBuilder.m:322-335,1064-1090`).

**A1. Package params (`ADJPackageBuilder.m`)** — these are ON the wire (via outputParams):

| key | value source (session pkg, `getSessionParameters` lines 349-396) |
|---|---|
| app_token | `ADJConfig.appToken` |
| app_version | `packageParams.buildNumber` (CFBundleVersion) |
| app_version_short | `packageParams.versionNumber` (CFBundleShortVersionString) |
| attribution_deeplink | constant `1` |
| bundle_id | `packageParams.bundleIdentifier` |
| control_params | **JSON dict of persisted server control params** (`[ADJUserDefaults getControlParams]`, lines 357/407/473/530/594/653/696/735/797/851/910) — present in EVERY package type incl. sdk_click & attribution |
| created_at | package creation time (epoch format) |
| default_tracker | config defaultTracker |
| device_name | `packageParams.deviceName` |
| device_type | `packageParams.deviceType` (e.g. phone) |
| environment | config environment (sandbox/production) |
| external_device_id | config externalDeviceId |
| fb_anon_id | packageParams.fbAnonymousId |
| installed_at | packageParams.installedAt |
| needs_response_details | constant `1` |
| os_name / os_version | "ios" / OS version |
| skadn_registered_at | `ADJUserDefaults skadn_register_call_time` date |
| started_at | session start epoch |
| push_token | activityState.pushToken |
| session_count / subsession_count / session_length / time_spent | activityState counters (persisted) |
| primary_dedupe_token | `activityState.dedupeToken` **if** `activityState.isPersisted` (lines 378-382) |
| secondary_dedupe_token | same token **if NOT persisted** (first session) |
| idfa | consent-gated; only if valid (not nil/empty/all-zeros) — `addConsentDataToParameters` (lines 1187-1287) |
| idfv | only if config.isIdfvReadingEnabled (lines 947-952) |
| tracking_enabled | only when ATT unsupported (line 1285) |
| att_status | ATT status int when supported (line 1280); refreshed pre-send by `updateAttStatus:inParameters:` (`ADJRequestHandler.m:236`) |
| ff_coppa / ff_skadn_disabled / ff_idfa_disabled / ff_idfv_disabled / ff_fb_id_disabled / ff_adserv_disabled / ff_att_disabled / ff_first_session_delay / ff_odm_enabled / ff_remote_triggers_callback | feature-flag `1`s, conditional (`injectFeatureFlagsWithParameters` lines 954-1006) |
| send_in_background_enabled / offline_mode_enabled / foreground / background | internal state flags (lines 954-974) |
| callback_params / partner_params | merged global+event callback/partner params (JSON) |
| last_skan_update | SKAN update JSON dict (lines 1008-1014) |
| store_name_from_client / store_app_id_from_client | config storeInfo (lines 1016-1024) |

Event package adds: event_token, currency, revenue, event_callback_id, transaction_id, deduplication_id, product_id, event_count, seq (`getEventParameters` 398-462).
Sdk_click package adds: source, reftag, referrer, click_time, deeplink, params (deeplink params JSON), purchase_time, adgroup/campaign/creative/tracker (last-known attribution), plus variant extras `attribution_token` (AdServices token, constant `ADJAttributionTokenParameter`, lines 23/226-230), `error_code`, `odm_info`, `content` (LinkMe) (`getClickParameters` 584-643).
Attribution package adds: initiated_by, needs_cost (`getAttributionParameters` 645-687).
Info pkg `/sdk_info`: + info_source-ish fields; AdRevenue: ad_revenue_*; Subscription: transaction_date, sales_region, etc.

**A2. Sending params (`ADJPackageHandler.m` `sendFirstI` lines 297-321 + `ADJRequestHandler.m` `updateSendingParameters` lines 178-188)** — also ON the wire:

- `queue_size` — only if queueSize-1 > 0
- `retry_count` — activityPackage.errorCount (always set; setInt skips only negatives)
- `first_error` / `last_error` — error codes, only if non-nil
- `wait_total` — totalWaitTime, only if > 0 (`setDouble` skips <= 0.0)
- `wait_time` — waitBeforeSend, only if > 0
- `sent_at` — NOW at send time (formatSeconds1970, same date format)
- Also note: `enqueue_size` is added to package params at queue time (`ADJPackageHandler.m:258-264`).

**A3. Pre-signing mutation (`ADJRequestHandler.m` `urlWithParams` lines 190-246):** if ATT-consent state changed between package creation and sending, `idfa` is added/removed and `att_status` updated IN the params map *before* `mergedParameters` is built. Claims and wire both see the mutated values.

### Claims INPUT map #2 — `extraParams`

| key | value | on wire? |
|---|---|---|
| client_sdk | `kClientSdk` = `@"ios5.8.0"` (`ADJUtil.m:34,137-139`) | no — not a wire param |
| activity_kind | `activityKindToString` → one of: `session`, `event`, `click` (**not** "sdk_click"), `attribution`, `info`, `gdpr`, `ad_revenue`, `subscription`, `third_party_sharing`, `measurement_consent`, `purchase_verification` (`ADJActivityKind.m:43-70`) | no |
| endpoint | `urlHostString` — full target URL from `ADJUrlStrategy` (`ADJUrlStrategy.m:12-22`): `https://analytics.adjust.com` (session/event/click/attribution default in v5.8.0 — **not** app.adjust.com), `https://consent.adjust.com`, `https://gdpr.adjust.com`, `https://subscription.adjust.com`, `https://ssrv.adjust.com`, with `.adjust.io` fallbacks | no — removed from outputParams and used for routing (`ADJRequestHandler.m:107-110`) |
| *(flattened control params)* | every key/value of the persisted `control_params` dict, per-key | they appear on wire ONLY inside the JSON `control_params={...}` param, not flattened |

### Persisted-state notes (the "uuid" question)

- **There is no `ios_uuid`/`adjust_uuid` wire param in v5.** The keychain item account `adjust_uuid` / service `deviceInfo` (`ADJUtil.m:1384-1430`) stores the persisted **primary dedupe token**; `activityState.dedupeToken` (NSCoding key `uuid`, `ADJActivityState.m:37,157-161,235`) is a lowercase random UUID (`generateRandomUuid`, `ADJUtil.m:1373-1379`) sent on the wire as `primary_dedupe_token` (or `secondary_dedupe_token` pre-persistence). So the "persisted install uuid" hypothesis is already satisfied on the wire by `primary_dedupe_token` — but the native core ALSO generates UUIDs internally (strings `getUUIDBytes`/`UUIDString`), so it may add its own.
- `adid` is server-issued (response only) and never enters the request map.
- SKAN fields (`last_skan_update`, `skadn_registered_at`) and `attribution_token` are wire params — see table.

---

## (c) Claims-only candidates the local search should test NEXT (ranked)

Given your verified Android result (claims = wire + [adj_signing_id, activity_kind, client_sdk, headers_id, native_version]) and the iOS SDK layer above, the iOS-only mismatch must come from either (i) extraParams the iOS core treats differently, or (ii) iOS exceptionKeys stripped from the wire but present in claims, or (iii) core-internal values. Ranked candidates:

1. **`endpoint`** — always present in iOS extraParams, never on the wire (the SDK consumes it for routing). Android-verified NOT in Android claims; the iOS core may still sign it. Candidate values to try: `https://analytics.adjust.com` (most likely for /session,/event,/sdk_click in v5.8.0; check the Host header of your capture), `https://app.adjust.com`, `https://consent.adjust.com`, `https://gdpr.adjust.com`, `https://ssrv.adjust.com`, `https://subscription.adjust.com`, and `.adjust.io` variants.
2. **`algorithm`** — value `adj9`. It is in the iOS exceptionKeys wire-strip list (so invisible in your capture if the core emits it into outputParams), and it is NOT one of your 5 constants.
3. **`secret_id`** — also in the iOS exceptionKeys list (v4 legacy). If the v5 core still injects/uses one, it would be claims-only. Try empty/absent last.
4. **Flattened `control_params` entries** — server-issued key/values persisted in NSUserDefaults (`adj_control_params`, saved from every response's `control_params` JSON, `ADJRequestHandler.m:438-441`). Handed per-key to the core. If your capture environment ever received `control_params` in an earlier response, the core may sign those entries while your wire-based reconstruction only sees the single JSON `control_params={...}` param (different sort/serialization). If your environment never received any, this is empty — verify via the presence/absence of `control_params` on the wire.
5. **Core-internal values (iOS-only divergence)** — the binary reads IDFV, bundle id, app receipt, and generates UUIDs. If any enter the claims (a nonce, an IDFV-derived value), they are unrecoverable from the wire alone and must be correlated with the `adj_verification` header component (decode its base64 and look for a matching UUID/IDFV/timestamp). This is the highest-risk platform divergence: the iOS core is a different codebase from the Android AAR.
6. **Wire-side caveat that can masquerade as a claims-only value**: the wire = core's `outputParams` (minus authorization/endpoint/exceptionKeys), so if the core reformats/drops any shared value (number formatting, trimming), your wire-derived claim stream is wrong at the source. Consider re-deriving mergedParameters from a debug build instead of from the wire.

Also worth checking in your search harness: `activity_kind` for sdk_click is `click`; sending-param values (`wait_total`/`wait_time`) only appear when > 0 and are `%.2f`-formatted before rounding; all dictionary params (callback_params, partner_params, control_params, params, last_skan_update, granular_third_party_sharing_options, partner_sharing_settings) are signed as compact JSON strings exactly as serialized by `NSJSONSerialization` (no spaces), with NSDate values pre-converted to `yyyy-MM-dd'T'HH:mm:ss.SSS'Z'Z`.

---

## (d) Simulator-build differences

- **None at code level.** Zero occurrences of `targetEnvironment(simulator)` or `simulator` in any .m/.h of ios_sdk v5.8.0. The `AdjustSigSdk.xcframework` simply ships an `ios-arm64_x86_64-simulator` slice with the identical signing code (a ~4.12 MB thin binary per slice). The capture being an ios-simulator build does not change the claims machinery.
- Behavioral (not conditional-compilation) differences to expect on a simulator: IDFA reads `00000000-0000-0000-0000-000000000000` without an AdSupport profile → rejected by `isValidIdfa` (`ADJPackageBuilder.m:1178-1182`) → `idfa` param ABSENT from wire and claims; AdServices `attributionTokenWithError:` typically unavailable → `attribution_token` sdk_click absent; `att_status` depends on the simulated ATT prompt.

---

## (e) Android v5 cross-reference (mirror confirmed)

Tag v5.8.0 (`Adjust/sdk-core/src/main/java/com/adjust/sdk/`):

- **`network/ActivityPackageSender.java` `signParameters` (lines ~137-170)** — exact structural mirror of the iOS function:
```java
Map<String,String> packageParams = new HashMap<>(activityPackage.getParameters());
packageParams.putAll(sendingParameters);                     // incl. "sent_at" (updateSendingParameters)
Map<String,String> extraParams = new HashMap<>();
extraParams.put("client_sdk", activityPackage.getClientSdk());
extraParams.put("activity_kind", activityPackage.getActivityKind().toString());  // "click" for sdk_click
extraParams.put("endpoint", urlStrategy.targetUrlByActivityKind(...));
JSONObject controlParams = SharedPreferencesManager...getControlParamsJson();
// flattened into extraParams, String values only
return AdjustSigner.sign(packageParams, extraParams, context, logger);
```
- **`AdjustSigner.java`** — reflective call into `com.adjust.sdk.sig.Signer` (closed `adjust-android-signature-5.0.0.aar` from `adjust/adjust_signature_sdk` releases; matches native_version 5.0.0). Same interface shape: (context, packageParams, extraParams, outputParams).
- **Wire construction** (`ActivityPackageSender.java:189-210, 325-460, 619-632`): POST body / GET query = `signedParameters` (= core's outputParams) verbatim, minus `authorization` (`extractAuthorizationHeader` removes it) and `endpoint` (`extractTargetUrl` removes it). **No exceptionKeys filtering exists on Android** — the core itself must keep signature fields out of outputParams.
- `control_params` is also a wire JSON param on Android (`PackageBuilder.java:307-308,407-408,464-465,581-582,646-647`).
- v5 vs v4: v4 used `sign:withActivityKind:withSdkVersion:` + `secret_id` on the wire; v5 moved to the two-dictionary `sign:withExtraParams:withOutputParams:` interface and `adj_signing_id` in the Authorization header (changelog: "Added support for SigV3 library. Update authorization header building logic to use `adj_signing_id`"). The legacy v4 selector is still compiled into the 5.0.0 core binary.
- **Implication for your iOS search:** since Android's verified claims exclude `endpoint` (it is provably not on the Android wire and your formula verified without it), the Android core demonstrably *filters* the extraParams bag. There is no guarantee the iOS core applies the same filter — `endpoint` is the single most likely iOS-claims-only key, followed by `algorithm`/`secret_id` (wire-stripped by iOS's exceptionKeys) and any core-internal (IDFV/nonce) value.

---

### One-paragraph summary

The iOS v5 SDK assembles the signed map in open code (`ADJRequestHandler.m`): map #1 = package wire params + send-time params (sent_at, queue_size, retry_count, first/last_error, wait_total/time); map #2 = {client_sdk="ios5.8.0", activity_kind ("click" for sdk_click), endpoint=<target URL>} + flattened persisted server control_params. Both go to the closed `AdjustSigSdk` core (`adjust_signature_sdk` v5.0.0 — matches native_version), whose outputParams then REPLACE the wire payload minus exceptionKeys {secret_id, signature, headers_id, native_version, algorithm, adj_signing_id}. The strongest untested claims-only candidates for the iOS mismatch are therefore `endpoint`, `algorithm`, `secret_id`, flattened control-param entries, and core-internal values (IDFV/nonce, correlated via `adj_verification`). No simulator-specific code exists.
