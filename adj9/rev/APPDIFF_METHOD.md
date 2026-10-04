# APPDIFF_METHOD — swapping adj9 onto another app

One tool, five app-specific inputs. Everything else in adj9 (the Random3 time
header, region d0/d2/d4, the claims law, the FinEx VM, the whitening cipher,
descriptor order `VA_ORDER`, the 192-B blob layout, the Authorization header
assembly) is **universal** and lives in `adj9sign/signer_simple.py` — do not
touch it when porting; only the five inputs below change.

## The SWAP CHECKLIST

Run first (accepts one APK or a directory; in a split APK set it auto-picks
the APK that carries the lib, and reads the cert from whichever APK you point
it at):

```bash
python adj9/rev/appdiff.py <apk-or-dir>            # --lib/--outdir optional
```

| # | item | where it lives | exact command | lands in |
|---|------|----------------|---------------|----------|
| 1 | **libsigner.so build** | `lib/arm64-v8a/libsigner.so` inside the APK (in a split set: `split_config.arm64_v8a.apk`, **not** base — appdiff.py probes siblings automatically) | `appdiff.py` prints sha256/size + `SAME-BUILD`/`DIFFERENT-BUILD` verdict (default reference: penti's lib at `extracted/arm64/lib/arm64-v8a/libsigner.so`) | `signer_simple.py` APPENDIX `_LIB_SPANS`. On `SAME-BUILD`: nothing. On `DIFFERENT-BUILD`: appdiff.py writes `span_*.bin` + a paste-ready `_LIB_SPANS_snippet.py` (spans `0x99000-0xBCA30`, `0x100094-0x12AA48`, `0x146000-0x149000`, vaddr==file offset) |
| 2 | **D9 descriptor** = signing-cert SHA-1 (20 B) | APK Signing Block (magic `APK Sig Block 42` before the central directory; pair ids v2 `0x7109871a`, v3 `0xf05368c0`, v3.1 `0x1b93ad61`; take the **leaf** cert, the last in the signer chain) | `appdiff.py` — the cert line flagged `<== LEAF cert -> this SHA-1 is the D9 descriptor` | `signer_simple.py` `DESC9` |
| 3 | **header constants**: `adj_signing_id`, `headers_id`, `native_version`, `adj_verification`, `Client-SDK` | ONE captured `Authorization` header of the app (proxy/MITM capture; **not in the APK**). `adj_verification` is invertible: `canonical.decode_adj_verification(<b64>)` cross-checks the claim | read the header fields directly | `signer_simple.py` `ADJ_SIGNING_ID`, `NATIVE_VERSION`, `ADJ_VERIFICATION`, and the hardcoded `headers_id` in `sign_request()`/`auth_header()`; `run_simple.py` `CLIENT_SDK` |
| 4 | **app identity**: `app_token`, `package_name`, `app_version` | `app_token`: capture or a `classes*.dex` string hunt (12-char Adjust token) — **not in the APK**. `package_name`/`app_version`: best-effort from the binary `AndroidManifest.xml` | `appdiff.py` prints ranked package/version candidates (the applicationId is the candidate that prefixes the most component names) | `run_simple.py` `APP_TOKEN`, `params["package_name"]`, `params["app_version"]` |
| 5 | **D8 descriptor** = 16-B flags constant | One captured signing's **descriptor dump** (`desc` map passed to `nSign` — Xposed oracle `adj9/module/` or hook `com.adjust.sdk.sig.NativeLibHelper.a`): descriptor `#8`. Note: the whitened record does *not* carry a D8 slot; D8 mixes into the digest — verify it by digest reproduction below (penti: `#8` was constant across all 10 captured signings, see `adj9/TASKS.md`) | `whiten_decoder.decode_blob()` on the captured blob verifies the rest of the record; D8 itself comes off the descriptor dump | `signer_simple.py` `DESC8` |

## Verification recipe (after filling the checklist)

1. **Decode the captured blob** — `python -c "import sys; sys.path.insert(0,'adj9/rev'); import whiten_decoder as wd, base64; r=wd.decode_blob(base64.b64decode(open('cap.b64').read()))['record']; print(r.hex())"`.
   Check: `r[25:45) == D9` (tag `03` at 24), seed `S = BE32(r[20:24))`, head at `r[3:19)`.
2. **Mint vs capture, byte-identical** — re-mint the captured signing with
   `signer_simple.sign_request(captured_params, kind, second=<captured second>, seed=<S>)`
   using the oracle-captured canonical claims; the full 192 B (record + digest)
   must match the capture. The digest `[160:192)` mixes **every** descriptor,
   so a wrong `DESC8`, `DESC9`, `CLIENT_SDK` or `ADJ_VERIFICATION` breaks it loudly.
3. **One live funnel** — `python adj9sign/run_simple.py` (fresh GAID, click fired
   before first session): `/click -> /session -> /sdk_click -> /attribution`
   must come back **non-Organic**. That is the only end-to-end proof.

## Penti ground truth (com.penti.app — validate appdiff.py against this)

| item | value |
|------|-------|
| libsigner.so | sha256 `55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc`, 1,366,632 B → **SAME-BUILD**; spans 145,968 / 174,516 / 12,288 B |
| D9 | `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` (745-B leaf cert, subject `localityName=Istanbul, organizationName=Penti`, serial `09F2EC1D`) |
| header | `adj_signing_id=1500000`, `headers_id=10`, `native_version=5.0.0`, `adj_verification=KlcAG2cbAAsKSl1KVi0FGiJbDHMI`, `Client-SDK=android5.7.0` |
| identity | `app_token=jut9tib0eeps`, `package_name=com.penti.app`, `app_version=3.14.0` (per `run_simple.py`; the shipped `_ref/base.apk` manifest shows 3.13.9 — **use the version of the build you impersonate**) |
| D8 | `bffffffffffffd1f0007000000000000` |
| ref APKs | `extracted/_ref/base.apk` (cert), `extracted/_ref/split_config.arm64_v8a.apk` (lib) |

Validate:

```bash
python adj9/rev/appdiff.py extracted/_ref/base.apk   # cert line must print fad0f10d...; lib SAME-BUILD
python adj9/rev/appdiff.py extracted/_ref            # dir mode picks the split, same verdicts
```

## Gotchas

- The base split carries **no lib** and may not be the lib carrier — always let
  appdiff.py probe; a lone base.apk with no sibling prints `UNKNOWN`.
- The leaf (last) certificate is D9; CA/intermediates are not. Only one cert
  exists on penti, but chained signers exist in the wild.
- The AXML string pool is often UTF-8 with a length byte that bleeds into
  appdiff.py's raw string scan (`Kcom.google...`); the prefix-recovery +
  prefix-count ranking handles it, but the candidate list stays best-effort —
  confirm the applicationId against a capture.
- Span offsets are vaddr==file offset **only** for those three ranges of the
  known libsigner layout; if a DIFFERENT-BUILD lib re-locates them, re-derive
  before trusting `_LIB_SPANS_snippet.py`.
