# _sub_ios_claims_law_RESULT.md — the iOS claims hunt: final state

Date: 2026-10-01.  Gap-closing stage after `_sub_ios_mint_RESULT.md`.
Oracle: `rec[46:78] == sha256_iv2(D9 ‖ 00 08 ‖ head16 ‖ LE32(S) ‖ SHA256("") ‖
tail17 ‖ claims)` — harness `_sub_ios_claims2_oracle.py`, **validated 9/9 on
the Android gold vectors** (real D9, `01‖00*16` tail) before any iOS run.
Corpus: the 30 signed Cainiao iOS requests (`consent.adjust.{io,com}`,
`Client-Sdk: ios5.8.0`, iPhone13,2 / iOS 26.5, ios-simulator build) — records
unsealed with the proven 30/30 pipeline, all non-claims fields byte-exact.

---

## 0. TL;DR verdict

**The iOS claims payload is still not reproduced, but the unknown is no longer
a composition problem — it is a single-value problem.**  This stage pinned the
signing-input structure exactly from the public Adjust iOS SDK v5.8.0 source,
exhausted every server-derivable composition of it (~52.4M new candidates on
top of the prior stage's ~15M; every run 0 hits on the oracle), and proved
there is no hidden per-install identifier anywhere in the capture.  The
remaining unknown is one or more values injected **inside the closed
`AdjustSigSdk` core** from device state it reads but the request never carries
(receipt / locale / timezone / nonce).  Practical consequence in §5.

## 1. What the SDK source now proves about the signing input

(From github.com/adjust/ios_sdk tag **v5.8.0** — matches the capture's
`Client-Sdk: ios5.8.0` and `native_version="5.0.0"`; mirror-confirmed against
android_sdk v5.8.0.  Full analysis: `_sub_sdk_source_RESULT.md`.)

* Signing happens in `ADJRequestHandler.m signWithSigPluginWithMergedParameters`
  (lines 582–639).  Input is **two dicts**:
  * map #1 `mergedParameters` = package params + sending params = **exactly
    the wire body params** of this capture (all values URL-decode back to the
    signed strings; verified `%2B`→`+`, `%20` spaces, compact JSON values);
  * map #2 `extraParams` = `client_sdk="ios5.8.0"`, `activity_kind`
    (`session`/`click`/`event`/`attribution` — never `sdk_click`),
    `endpoint` = the base target URL (e.g. `https://consent.adjust.io`), plus
    flattened persisted `control_params` (**empty here** — no Adjust response
    in the capture carries `control_params`).
* The wire body is the core's `outputParams` minus exceptionKeys
  `{secret_id, signature, headers_id, native_version, algorithm,
  adj_signing_id}` — so `algorithm="adj9"` and `secret_id` are iOS-only
  *possible* claims keys invisible on the wire (both tested, §3).
* The Android frida mapget logs (`_sub_event_signings.json`) show the native
  core reads its keys in **one alphabetical run** and injects exactly one
  value itself — `adj_verification = b64(key19 ⊕ '{"os_name":"<os>"}')` —
  which is read back as the first profile key.  The iOS core is the same
  family (same `native_version 5.0.0`, `headers_id 10`, `adj_signing_id
  1500000`), so the working law was:
  `claims = sorted(pool) ‖ "1500000" ‖ sorted(tail) ‖ kind ‖ "ios5.8.0" ‖ "10" ‖ "5.0.0"`.
* **The capture is an ios-simulator build**: the core rewrites the platform
  string (`adj_verification` decodes to `{"os_name":"ios-simulator"}` while
  the wire `os_name=ios`).  If the core rewrites the `os_name` *claim* the
  same way, every earlier candidate was 6 bytes wrong.  Tested (§3).
* There is **no `ios_uuid`/`adjust_uuid` in v5**: the persisted install UUID
  *is* `primary_dedupe_token` (keychain item account `adjust_uuid`) and it is
  on the wire.

## 2. Capture mining results (data mines 1–2 of the task)

* **~150 `<app>iosmodd.py` replay scripts** (`D:/model_training/my_projects/
  all_working_scripts/` + `D:/my_personal_projects/my_code/`): all are
  **AppsFlyer** replay scripts (`tracker.appsflyer.*` imports; campaign_data
  blocks).  Zero Adjust/adj9/signature/claims content — nothing to reuse.
* **Other iOS captures on disk**: credcol iOS11 saz (57 iOS requests —
  AppsFlyer endpoints `app-analytics-services.com`, **no Adjust**),
  slimkitwalking iOS11 (249 iOS requests, no signatures), nike iOS11
  saz/chls (81 iOS requests, no Adjust hosts, no signatures), pulz/derayah/
  avito chls (Android only).  `*.saz/*.chls/*.har` swept across
  `C:/Users/Apps/Downloads` (recursive) and `D:`.
* **Conclusion: the 30 cainiao requests remain the ONLY iOS adj9 corpus on
  this machine.**  Cross-app validation of the law is impossible locally;
  a second app's iOS capture (or one instrumented simulator signing) is
  required to close the law.

## 3. The searches (all on the session record 0144 unless noted)

Oracle harness first reproduced the 9 Android gold blocks byte-exactly, then:

| stage | space | n | hits |
|---|---|---:|---:|
| A | explicit laws: every-wire-key pool ± endpoint(5 values) × tail × pinned, Android-analog | 45 | 0 |
| B | **every membership subset** (2^18) of the 26 wire keys × endpoint{none,.io,.com,bare host,+path} × tail{∅,session_count,started_at,+} × pinned{after,absent}, sorted, BLOCK2 last | 10,485,760 | 0 |
| C | same + **adj_verification** ∈ {absent, f(ios-simulator), f(ios), plain JSON} as pool member (signer-computed, Android-proven pattern) | 4,194,304 | 0 |
| D | **frame × membership cross**: 4 BLOCK-tail frames (`02‖dev`, `01‖00*16`, `02‖00*16`, `01‖dev`) × full membership × device_name excludable (it lives in the record) × adj_verification × tail × pinned | 25,165,824 | 0 |
| E | modes {BLOCK2-last, no-envelope, pinned-first} × endpoint × adj_verification × full subsets (partial run; unique full-membership cells re-run exactly) | 27+ | 0 |
| F/G | **combined final pool**: wire keys × os_name ∈ {ios, ios-simulator} × adj_verification(3) × endpoint(4) × **algorithm=adj9** × tail × pinned × 2 frames | 12,582,912 | 0 |
| H | envelope permutations (canonical, +algorithm tail, pinned-inside-BLOCK2, client_sdk-first, no-envelope, pinned-at-end) × full pools × os_name × frames | 432 | 0 |
| JSON | claims as compact/sorted JSON dict (incl. envelope keys inside) + JSON value arrays — motivated by `NSJSONSerialization` in the core's imports | 144 | 0 |
| derived | core-injected hash probes: sha256/sha1/md5 (hex+b64) of idfv/idfa/adid/primary_dedupe_token (5 normalisations × 6 sources) under 8 plausible key names, profile+tail | 2,880 | 0 |
| serial | k=v / k=v& / k=v; / k:v / val& / val\| / 2-B BE-LE + 4-B BE length-prefixed, sorted + wire order | 960 | 0 |
| **total new** | | **~52.4M** | **0** |

Integrity checks along the way: wire `+` only ever appears as `%2B`
(`adjUrlEncode` escapes `+`→`%2B`), so URL-decoded values equal the signed
map values; response JSON confirms the single server-side identifier
(`adid=baa52143f2b91a6ce1c1e04aa3c15ca1`); no retried-package endpoint
ambiguity affects the session record (both endpoint values tested).

## 4. The non-wire value hunt (task item 4) — negative, decisively

Swept all 3476 request + response records of the 55 MB capture (gzip/deflate
decoded) for uuid-shaped (8-4-4-4-12) and 32-hex strings:

* **Zero uuid-shaped strings outside the signed bodies.**  The only uuids in
  the entire capture are `idfa`, `idfv`, `primary_dedupe_token` — all on the
  wire.  `callback_params.deviceId` (`anXOiLrUbRkDAItAE72AloZa`) is 22-char
  base64ish, on the wire.
* The only non-wire identifier the server holds is the **adid**
  (`baa52143f2b91a6ce1c1e04aa3c15ca1`, echoed by all 30 responses); the
  Android gold maps prove the core's input map never contains the adid, and
  every adid-keyed candidate failed.
* The v5 SDK has no client uuid beyond the dedupe token (keychain
  `adjust_uuid` = the persisted **dedupe token**, on the wire).  The "hidden
  install uuid" hypothesis is **dead** — if a uuid is in the iOS claims, the
  core generates it internally (`CFUUIDGetUUIDBytes` is in the binary's
  imports) and it exists nowhere else.

## 5. Where this leaves the law — classification

**Fully solved and minter-ready (`_sub_ios_mint.py`, 30/30 on every byte
except the BLOCK):** header MINSTD law, region/d0, record container + the 3
iOS deviations, whitening, digest MAC, auth-header envelope
(`adj_signing_id="1500000"`, `algorithm="adj9"`, `headers_id="10"`,
`native_version="5.0.0"`, `adj_verification = f(os_name)` — simulator build
sends the `ios-simulator` form), `Client-Sdk: ios5.8.0`.

**Per-install values — generate fresh, exactly like the Android funnel
(SUCCESS class):** `idfv` (fresh per install), `idfa` (device-provided or
zeroed), `primary_dedupe_token`/`secondary_dedupe_token` (SDK-generated UUID —
mint + persist), `created_at`/`sent_at`/`installed_at`/`started_at` (clock),
counters (`session_count`, `subsession_count`, `event_count`, `seq`,
`session_length`, `time_spent`, `enqueue_size`, `retry_count`, `queue_size`),
`att_status`, `attribution_token` (device AdServices token), `fb_anon_id`
(app-scoped), `callback_params` JSON, `event_token`, `last_skan_update`/
`skadn_registered_at` (SKAN state), `source`.  App constants (`app_token
hd3rt9fm33sw`, `bundle_id`, `app_version`/`_short`, `device_name`/
`device_type`, `environment`, `os_name`/`os_version`, `needs_response_details`,
`attribution_deeplink`, `send_in_background_enabled`, `offline_mode_enabled`,
`foreground`) are copied verbatim.

**Remaining mystery (precise):** the exact bytes of the claims string inside
the BLOCK pre-image.  After ~67M candidates (this stage ~52.4M + prior ~15M)
covering *every* subset of the fully-enumerated server-derivable pool —
wire params ∪ {client_sdk, activity_kind, endpoint, algorithm, secret_id,
adj_verification, control_params} — under bare-concat (sorted/wire order),
JSON, k=v-family and length-prefixed serializations, 4 BLOCK-tail frames,
envelope permutations, pinned placements, and the simulator os_name rewrite:
**zero matches**.  Combined with the decisively negative non-wire hunt, the
remaining explanations, ranked:

1. **A core-internal claims value not on the wire and not server-derivable** —
   the closed `AdjustSigSdk` binary (obfuscated; key list not extractable
   from strings) imports `appStoreReceiptURL`, `NSLocale`, `NSTimeZone`,
   `CFUUIDGetUUIDBytes` — value sources the Android core never uses.  If the
   injected value is a nonce/receipt-hash, **the Adjust backend cannot
   re-derive the iOS claims either** and cannot be verifying the BLOCK beyond
   the digest/structure checks — in which regime fresh-minted blobs with a
   well-formed fabricated claims string pass the same server checks the
   genuine ones pass (unverified without one live test).
2. **A hand-ordered iOS key list** (emission order ≠ alphabetical) —
   unsearchable without the deobfuscated key list from the
   `AdjustSigSdk` arm64 binary (1.9 MB, strings runtime-decoded).
3. A serialization family outside §3 (low residual probability).

**The one experiment that settles it:** instrument one ios-simulator signing
(frida hook on `ADJSigner sign:withExtraParams:withOutputParams:` dumping both
input dicts, or on the core's SHA-256 compression entry) — exactly the method
that produced the Android `adj9/device` traces and settled the Android law in
one signing.  `mint_ios(claims=...)` reproduces the capture byte-for-byte the
moment the string is known; alternatively the live ARM run (fresh-mint against
production, as done on Android in ARM C/D) directly tests hypothesis 1's
"server cannot verify the block" consequence.

## 6. Artifacts (all new; nothing existing modified)

* `_sub_ios_claims2_oracle.py` — corpus loader + numpy BLOCK-oracle harness
  (Android-gold-validated 9/9).
* `_sub_ios_claims2_search.py` … `_sub_ios_claims2_search7.py` — stages A–H
  (search5 = standalone Stage F variant, superseded by search6's combined run).
* `_sub_ios_claims2_out.json` — per-stage candidate counts, hit lists, notes.
* `_sub_ios_claims2_fg.log` — stage F/G run log.
* `_sub_sdk_source_RESULT.md` (sibling) + `_scratch_sdk/` — SDK source basis.
