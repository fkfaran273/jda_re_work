# adj9 cross-app check — com.creditsea.app vs com.penti.app (2026-09-29)

Source APKs (original Play delivery, base + 9 splits):

- `C:\Users\Apps\Documents\adjust_Apps\com.creditsea.app\base.apk` — 94,900,419 B,
  SHA-256 `d57d5ef2635e8b22c4c6fc03639805fc324a9823de5f1f97aa0a881ff518e194`
- `...\com.creditsea.app\split_config.arm64_v8a.apk` — 33,715,164 B,
  SHA-256 `8624b9e9bb68cd26c18fe3546406f520279831ddeaa1d1aa9cdf826df01171c6`
- Note: `creditsea_base.apk` already in the workspace root (Sep 21) is **byte-identical**
  to the new target's base.apk (same SHA-256).

Artifacts saved here:

- `libsigner.so` — extracted from `split_config.arm64_v8a.apk:lib/arm64-v8a/libsigner.so`
- `cert_v2_00.der` — creditsea signing cert (from APK Signing Block, v2 id 0x7109871a;
  the v3 block 0xf05368c0 carries the same single cert; no v3.1 block present)
- `_penti_cert.der` — penti cert re-extracted from workspace `base.apk` signing block
  (the old `base.apk.cert.der` in the workspace root has a 4-byte length prefix
  `e9 02 00 00` prepended, which is why it fails DER parsing)
- `libapp.so` — creditsea Flutter Dart snapshot (token hunt)
- `_dexstrings.txt` — full string pools of all 5 creditsea dexes
- `_ex/AndroidManifest.xml` — decoded manifest

## Comparison table

| item | penti (com.penti.app) | creditsea (com.creditsea.app) | same? |
|---|---|---|---|
| libsigner.so size | 1,366,632 B | 1,366,632 B | YES |
| libsigner.so sha256 | `55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc` | `55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc` | **BYTE-IDENTICAL** |
| libsigner.so sha1 | `9756ac831c82f77677c319e4671df1d85f4e3855` | `9756ac831c82f77677c319e4671df1d85f4e3855` | YES |
| lib verdict | adj9 VM signer (whitener at `sub_1441e4`, OP_RAND PLT thunk at 0x148d10, main range 0x100094–0x12aa48) | same binary — all `_LIB_SPANS`, whitener call-site literals and OP_RAND offsets carry over unchanged; no disassembly delta to check | YES (same algorithm implementation, not even re-obfuscated) |
| signing cert | 745-B DER, SHA-1 `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd`, subject `O=Penti, L=Istanbul`, self style (uploader), valid 2020–2045 | 1,421-B DER, SHA-1 `06f5ffcee0541608765407ab9e0180e7b1b7e7d0`, SHA-256 `41413d130087a5350b4a93b949bd4492410b959f8b0e121db4527df94590f504`, subject `CN=Android, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US` (Google Play app signing), valid 2025-03-13 – 2055-03-13, serial `0xb561d5c9128271de27f97e5ad758cc4dfab3594f` | **NO — must swap D9** |
| package | com.penti.app | com.creditsea.app | NO |
| versionName / versionCode | (penti: 5.x app) | 1.0.174 / 354 | NO |
| app framework | native Android (no libapp.so/libflutter.so) | Flutter (libflutter.so 11 MB, libapp.so 15.8 MB, Dart pkg `package:creaditsea_app/...`) | NO |
| app_token | `jut9tib0eeps` (from capture; NOT present anywhere in penti's APK bytes) | best candidate **`i2n2e5kmcpvk`** — isolated 12-char `[a-z0-9]` pool string in libapp.so at 0x10e0e5, format-matched to penti's token (3 digits of 12). Secondary weak candidate `handptrtsld1` (1 digit, near unrelated identifiers). `8ab2398e57f5` rejected (is the tail of UUID `76621ebb-ba91-463b-92db-8ab2398e57f5`). Neither candidate occurs in base.apk (token lives only in the arm64 split's Dart snapshot). Confirm by capture (D8) | NO (unconfirmed candidate) |
| adj_verification | `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` | identical value expected: 5.8.0 SDK computes it the same way (`o3.a(a0)` → serialize `Data(osName=android)` → UTF-8 → XOR `s2.a`, `i % 19` → Base64 NO_WRAP); `s2.<clinit>` fill-array payload is the SAME 19-byte key `Quoh8uafohgh7CahM2h`; recomputed = `KlcAG2cbAAsKSl1KVi0FGiJbDHMI`. Pent's captured value does not appear as a dex literal (it is computed), and neither does the key as a string — the key is a fill-array-data payload in classes.dex | YES (SDK constant, app-independent) |
| Client-SDK header | android5.7.0 | android5.8.0 (`com.adjust.sdk.Util.getSdkVersion` / `DeviceInfo.getClientSdk` const-string; sig SDK classes still at `com.adjust.sdk.sig.*`, incl. `u2`, `t1`, `d3`, `o3`, `s2`, `NativeLibHelper`) | NO (version) |
| adj_signing_id | 1500000 | injected into the map after nSign returns (same u2.a static reads `adj_signing_id`/`headers_id`/`algorithm`/`native_version` back out of the map; only ~579 printable strings in the .so, no plaintext constants — VM-obfuscated). Identical .so ⇒ expected **1500000**; confirm via capture | YES (expected, from identical native lib) |
| headers_id | 10 | same reasoning ⇒ expected **10**; confirm via capture | YES (expected) |
| native_version | 5.0.0 | same reasoning ⇒ expected **5.0.0**. (The `5.0.7` string in classes3.dex is the Firebase Crashlytics registrar version — NOT the sig SDK version) | YES (expected) |
| algorithm | adj9 | `Signature %s,%s,%s,%s,%s,%s` format string present, `u2.a(LinkedHashMap,[B)` builds the same 6-field header with `%s="%s"` pieces (signature, adj_signing_id, algorithm, headers_id, native_version, adj_verification) | YES |
| adjust_config.properties | n/a | SDK reads it (`ActivityHandler.readConfigFile`) but the file is absent from the APK and resources.arsc — no overrides | same behavior |
| Adjust manifest meta-data | n/a | none (token is set in Dart code via `initalizeAdjustSDK` / `AdjustConfig` of the adjust_sdk Flutter plugin) | — |

## Verdict: algorithm vs app-specific

**Algorithm-shared (nothing to re-derive):** the entire native signing VM —
`libsigner.so` is byte-identical, so `adj9sign/adj9_signer.py` `_LIB_SPANS`,
`S.region`, `WIN_HEAD` (d0 phases), the whitener semantics at `sub_1441e4`
(const 0x30/0x2b/0x34/0x37/0x38/0x3b/0x3c/0x35/0x36/0x2d/0x48/0x05 call sites),
OP_RAND, `finex_mint`, envelope field order (`VA_ORDER`) and the header
assembly (`Signature %s,...` 6 fields, adj9) all carry over untouched.
`adj_verification` is a shared SDK constant (same 19-byte XOR key in both apps'
dexes) — value `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` for creditsea too. The sig SDK
Java layer is the same `com.adjust.sdk.sig` package (v5.8.0 of the main SDK).

**App-specific (must swap to sign for creditsea):**

1. **lib spans** — no change. Byte-identical lib (`55353b75…`); all `_LIB_SPANS`
   in `adj9sign/adj9_signer.py` carry over unchanged.
2. **cert D9** — swap `D9 = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` →
   `D9 = 06f5ffcee0541608765407ab9e0180e7b1b7e7d0` (creditsea SHA-1, 20 B; DER
   saved as `cert_v2_00.der`). Note the server knows this digest from the Play
   signing cert; if it instead pins the pre-Play upload cert, that value must
   come from a capture.
3. **app_token** — `jut9tib0eeps` → **`i2n2e5kmcpvk`** (format-matched candidate
   from libapp.so; ground-truth it against a live creditsea capture before use).
4. **header constants** — keep `adj_signing_id=1500000`, `headers_id=10`,
   `native_version=5.0.0`, `algorithm=adj9`, `adj_verification=KlcAG2cbAAsKSl1KVi0FGiJbDHMI`
   (all from the identical native lib / shared SDK constant); change
   `CLIENT_SDK` to **android5.8.0** and `package_name` to **com.creditsea.app**.
5. **D8-from-capture** — `D8 = bffffffffffffd1f0007000000000000` stays a
   capture-sourced constant; refresh from a live creditsea signing capture on
   the target device (it may be device- rather than app-derived, but it must be
   confirmed before first mint).
