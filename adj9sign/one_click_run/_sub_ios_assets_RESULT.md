# iOS assets + Adjust signing-time dataset + SDK fingerprint (subagent report)

Date: 2026-10-01. Source SAZ: `C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz` (55,066,175 bytes, 3476 sessions).

---

## TASK A — iOS app binary search

Searched (maxdepth 4, case-insensitive) `C:/Users/Apps/Downloads`, `C:/Users/Apps/Desktop`, `C:/Users/Apps/Documents` for: `*.ipa`, `*.app`, `Payload/`, `*.dSYM`, `Adj*`, `libsigner*`, `*.framework`, `*class-dump*`, `*decrypted*`, `*.dylib`, plus large `*.zip` (possible renamed IPA).

**Result: no iOS binary available.**

- No `.ipa`, no `.app` bundle, no `Payload/`, no `.dSYM`, no decrypted iOS binaries, no Adjust iOS frameworks, no class-dump outputs anywhere in the three roots.
- Only matches were false positives: Python scripts/logs named `adj9*` / `adjust*`, and `C:/Users/Apps/Documents/adjust_Apps/penti_android/extracted/libsigner.so` (the already-analyzed ANDROID signer, not iOS).
- Only large zip: `C:/Users/Apps/Documents/appsflyer_apps/com.polymarket.android.zip` (Android, irrelevant).
- Conclusion: the native iOS signer (`libsigner` / Adjust iOS SDK binary) must be obtained from elsewhere (decrypted IPA / device dump); nothing on this machine.

---

## TASK B — Signing-time dataset (30 signed Adjust requests)

Output: `C:/Users/Apps/Downloads/com.penti.app/adj9sign/one_click_run/_sub_ios_timing.json` (82,535 bytes).

Selection: `raw/NNNN_c.txt` headers containing `signature="` → exactly 30 requests (matches expectation). SAZ m.xml SessionTimers were in `+05:30` local time; all timestamps converted to unix epoch floats (UTC).

Per-request fields: `sid` (SAZ file number), `sid_xml` (Session SID attr), `method`, `host`, `path`, `kind`, `client_sdk`, `user_agent`, full `authorization` block (algorithm, adj_signing_id, headers_id, native_version, signature_b64 256 chars, signature_decoded_len, adj_verification_b64, header16_hex), `ui_comment`, `timers_iso`, `timers_unix` (12 timestamp fields), `durations_ms`, `signing_seconds` (plausible signing-second window), `flag_bits`, `pipe_reused`.

### Key facts

| Property | Value |
|---|---|
| Signed requests | 30 (sdk_click: 2, session: 1, event: 26, attribution: 1) |
| Hosts | `consent.adjust.com` (26), `consent.adjust.io` (4) |
| Kind | sdk_click / session / event / attribution (first 5 requests are sdk_click, sdk_click, session, event, attribution) |
| algorithm | `adj9` (all 30) |
| adj_signing_id | `1500000` (all 30) |
| headers_id | `10` (all 30) |
| native_version | `5.0.0` (all 30) |
| signature | 256-char base64 = 192 bytes; 30 DISTINCT signatures (all unique) |
| header16 (adj_verification decoded, 16 bytes, hex) | **identical in all 30 requests**: `2a57001b671b000b0a4a5d4a5e2c12453e5b0524190e1c5707431b` |
| app_token | `hd3rt9fm33sw` (Cainiao global iOS) |
| adid (from responses) | `baa52143f2b91a6ce1c1e04aa3c15ca1` |

### Signing windows (unix seconds, floor(ClientConnected) .. floor(ClientBeginRequest))

Signing necessarily happened inside these windows (the client signs before Fiddler sees the request headers):

- Window widths: 1 s × 5 requests, 2 s × 23, 3 s × 1 (sid 2959), 4 s × 1 (sid 2903).
- First signed request: sid 142, ClientConnected = 1787553341.338 (2026-08-24 06:05:41.338 UTC = 12:05:41 +05:30).
- Last: sid 3429 at 1787557517.687 UTC. Whole signed span ≈ 69.6 min.
- The per-request candidate second sets are in `_sub_ios_timing.json` under `signing_seconds.candidates`.

### ui-comments (SessionFlags)

sid 142, 143, 144, 157, 170 = "app open"; 454, 1068 = "login"; 1144 = "popup click"; 1451 = "checkout"; 1908 = "add address"; 1949 = "manage address click"; 2564 = "package resgiter" (sic); 18 requests have empty comment.

Note: `sent_at`/`created_at` inside the POST bodies carry `-0700` offsets (device local time, e.g. `created_at=2026-08-23T23:35:32.342Z-0700`) while Fiddler ran at `+05:30`; the JSON stores everything as UTC epoch floats so both reconcile.

---

## TASK C — SDK fingerprint from the capture

Scanned all 3476 `_c.txt` and 3476 `_s.txt`, including gzip/deflate-decompressed response bodies (brotli bodies not present/decodable).

### Needle hits

| Needle | Files hit | Where / meaning |
|---|---|---|
| `adj9` | 30 | ONLY in the 30 signed request `Authorization` headers. Zero occurrences in any response. |
| `native_version` | 30 | Same — request headers only (`native_version="5.0.0"`). |
| `adj_signing_id` / `signing_id` | 30 | Request headers only (`adj_signing_id="1500000"`). |
| `adj_verification` | 30 | Request headers only (16-byte value, constant). |
| `headers_id` | 30 | Request headers only (`headers_id="10"`). |
| `5.8.0` | 30 | Request headers only, inside `Client-Sdk: ios5.8.0`. |
| `Adjust` | 41 | TLS server certificates (`CN=*.adjust.io` / `CN=*.adjust.com`, `O=Adjust GmbH, L=Berlin, S=Berlin, C=DE`, issuer DigiCert Global G2 TLS RSA SHA256 2020 CA1) + domains. |
| `adjust` (lowercase) | 166 | Adjust domains + unrelated JS/CSS tokens (`adjustX`, `fontSizeAdjust`, `autoAdjustOverflow`, etc.) in webview HTML/JS. No Adjust SDK framework strings. |
| `sdk_version` | 418 | All from Alibaba **aplus** JS analytics SDK inside taobao webview content (`t.sdk_version=m`, `sdk_version:Zo`) — NOT Adjust. Response-body hits: only 4 files (0249, 1169, 1526, 2257), all aplus JS. |
| `signer` | 2 | Only `createAssigner` (underscore.js token). No `signer`/`libsigner` strings anywhere. |

### Distinct values on signed requests

- **User-Agent (1 distinct):** `Cainiao/57505987 CFNetwork/3860.600.12 Darwin/25.5.0`
- **Client-Sdk (1 distinct):** `ios5.8.0` → Adjust iOS SDK 5.8.0, native signer `native_version=5.0.0`, signing id `1500000`, algorithm `adj9`, `headers_id=10`.
- Body parameters also show: `os_name=ios`, `os_version=26.5`, `device_name=iPhone13,2`, `device_type=iPhone`, `bundle_id=com.cainiao.cnintl4iphone`, `app_version=57505987`, `att_status=3`, `source=apple_ads` (organic attribution response: `tracker_name=Organic`).
- Note: capture filename says "ios12" but the traffic self-reports iOS 26.5 (Darwin 25.5.0) — the label does not match the device OS on the wire.

### Distinctive framework names

No framework names leak over HTTP (expected). Nothing like `AdjustSdk.framework`, `AdjustWebBridge`, or `libsigner` appears anywhere in requests or responses. The only server-side Adjust identity is the TLS certificate (`O=Adjust GmbH`) on `consent.adjust.com` / `consent.adjust.io`.

### Endpoint accounting

All Adjust traffic is the 30 CONNECT tunnels plus exactly the 30 signed API calls (2× `/sdk_click`, 1× `/session`, 26× `/event`, 1× `/attribution`). No unsigned Adjust API calls (no `/gdpr`, `/subscription`, `/sdk_redirect` etc.). All 30 responses: HTTP 200, tiny JSON `{"app_token":"hd3rt9fm33sw","adid":"baa52143f2b91a6ce1c1e04aa3c15ca1"}` (attribution response additionally carries the Organic tracker block; session response adds `"ask_in":2000`).

---

## Outputs

- `C:/Users/Apps/Downloads/com.penti.app/adj9sign/one_click_run/_sub_ios_timing.json` — 30-record signing-time dataset.
- `C:/Users/Apps/Downloads/com.penti.app/adj9sign/one_click_run/_sub_ios_assets_RESULT.md` — this report.
- No other files modified. (SAZ was extracted read-only to a temp dir `C:/tmp/saz_ios/` for analysis.)
