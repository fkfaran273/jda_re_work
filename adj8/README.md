# adj8 — xyz.be.customer (Adjust Signature SDK 3.67.0, algorithm "adj8")

Port of the manual_run/adj9 workflow to the adj8 generation, for app
`xyz.be.customer` (the "be" Vietnam super-app, versionName 2.6.153).

```
python -u run_install.py --dry-run     # signs, sends nothing
python -u run_install.py               # live: click -> session -> click -> attribution
```

Needs `unicorn` (pip install unicorn): each signature = one emulation of the
genuine 3.67.0 libsigner.so (~30 s).  Everything else is network time.

## The envelope

```
blob(176) = header(16) || body(128) || tag(32)

header   bionic rand() pair-XOR law, seed = the signing second
         (310-draw warm-up, 8 draws, w_i = d_2i ^ d_2i+1, BE u32) — verified
         18/18 on the real captures.  Same law as adj7/adj9.
body     computed by the genuine native under Unicorn (embedded, no files).
         Off-device the native signs through its internal default key path
         (same finding as adj7); the server-verifiable part is the tag.
tag      HMAC-SHA256(DK38, blob[16:144]), DK38 = the lib constant
         caab83444a2146392abb96b64230615529a770c63c163c1c7528673e0671728f
         (movz/movk run @0xf9014) — verified 18/18 on the real captures.
claims   built inside the native: the 97-key pool (95 sorted keys +
         activity_kind, client_sdk), present keys only, values concat'd bare,
         pinned adj_signing_id "1400000" right after package_name, split at
         session_count.  Verified BYTE-EXACT against the native's own claims
         buffer.  (3.62.0's law carries over unchanged.)

auth     Signature signature="<BASE64>",adj_signing_id="1400000",
         algorithm="adj8",headers_id="9",native_version="3.67.0"
         (algorithm BEFORE headers_id — 3.67.0 uses the adj9 order;
         signature is base64, unlike 3.62.0's upper hex)
```

Generation ladder (from adj7_work): adj5=3.32.0/1100001/h5 · adj6=3.47.0/1200000/h5 ·
adj7=3.62.0/1300000/h8 · **adj8=3.67.0/1400000/h9** · adj9=5.0.0/1500000/h10.
Blob: adj7 304 B, **adj8 176 B**, adj9 192 B.  `adj_verification` does not exist in 3.x.

## Evidence chain

1. Device-pulled `split_config.arm64_v8a.apk` carries `libsigner.so`
   1,304,840 B — **byte-identical** (md5 6a9dee86a51fc3305703844460771399)
   to the official `adjust-android-signature-3.67.0` release
   (`extracted/_ref/sigs/sig367_arm64_v8a.so`).  Its XOR-obfuscated `.data`
   contains `adj8` @0x13aeec (key 0xdb) — the algorithm token itself.
2. 38 real adj8 signatures in `adj7_work/CORPUS.json` (derayah / m4marry /
   pulz captures, client_sdk `android5.6.1`; 18 unique blobs).  NOTE: the
   corpus `sig_bytes=118` field is wrong — every blob decodes to 176 B.
3. Tag law + header law verified on those 18; claims law verified against
   the native's own buffer during emulation (`work/`).
4. `work/adj8_replay1.py`: mint from the derayah 0004 session map — header
   byte-identical to the genuine capture, tag verifies, body diverges from
   byte 16 exactly like adj7 (per-install H vs the native's default-H).
5. Wire format identical to adj9's builders: session 44 fields, click 48,
   no mcc/mnc, no activity_kind/client_sdk on the wire.

## App specifics (xyz.be.customer)

| value | source |
|---|---|
| package `xyz.be.customer`, v2.6.153 | device pm/dumpsys |
| cert_sha1 `07e6d5074866a3b8e1fb6efcb4714aff91624550` | META-INF/BNDLTOOL.RSA of the pulled base.apk |
| client_sdk `android5.7.0` | dex string (no flutter composite) |
| app_token | **NOT in the APK** — runtime config from gw.be.com.vn, login-gated; not readable without root.  Fill from the Adjust dashboard into `apps.json` (`_note_app_token` there). |
| click_link | the team's tracker URL — fill into `apps.json` |

The device_data.json is the connected moto g42's real profile (adb getprop).

## Files

| file | what it is |
|---|---|
| `adj8_pure.py` | the self-contained signer (embedded native + laws) |
| `run_install.py` | the funnel runner |
| `apps.json` | campaigns (`customer`) |
| `device_data.json` | the device profile |
| `apks/` | device-pulled base + splits |
| `lib/`, `cert/` | extracted libsigner.so and signing cert |
| `work/` | the analysis: capture data, immruns, tag hunt, header law, emu harness |
| `cap/` | device-capture workspace (mitmproxy setup; app ignores proxy — see below) |

## What did NOT work for pulling the app_token (so nobody retries)

adb shell has no su (Magisk present but su hidden).  The bridged mitmproxy CA
from the Sep session is still in /system/etc/security/cacerts (8bbe0e8d.0 ==
~/.mitmproxy/mitmproxy-ca-cert.cer) and mitmdump works over `adb reverse`,
but the app ignores the global http_proxy (Flutter/Dart networking goes
direct), and its config fetch is login-gated anyway.  `adb backup` of the
package returns 47 bytes (backup opted out).  The token is not in the APK,
resources.arsc, or the Dart snapshot.

## Attribution diagnosis (2026-10-03): installs book ORGANIC — tracker-side issue

The funnel runs perfectly (click reftag, /session 200 + adid, /sdk_click 200)
but attribution never leaves Organic. Hard evidence that this is NOT a
client/signature problem:

1. A GENUINE device install was tested: the connected moto g42 clicked the
   mobpine link (offer 23472302), installed from the Play Store, and the app's
   own SDK reported the install_referrer sdk_click with the real reftag
   (cliSIf0PsDdZA, click_time 00:34 local). Its attribution: **Organic**,
   engagement_time zero (adid 0ba4b4efb422f74582e0be3b01f76417, gaid
   992bd9da-7e5c-4e75-82dc-27e60648af05 — captured via the LSPosed oracle,
   see below).
2. Our offline funnel against offer 23492471: same result.
3. Our offline funnel against offer 23472302 with sub3={gaid} (mobpine
   forwards it as gps_adid into the go.link click — a device-matched click):
   same result.

Both offers resolve through begroup.go.link: offer 23492471 ->
adj_t=23kcsfku (NN102_DNGT), offer 23472302 -> adj_t=2390uba9 (DNS_ADD /
ADD_Arb_21_RFAMP_). The tracker must be checked in the Adjust dashboard for
app_token 7z9fjy072rgg: whether those adj_t trackers belong to this Adjust
app at all, are enabled, and have attribution windows/click timeframes set.
The client flow is indistinguishable from a genuine device (server accepts
every request; only the pairing fails).

## The APK requirement

The 3.67.0 native parses the APK file itself during signing: it walks the
zip / signing block through `fopen`/`fread`/syscalls (observed step by step
in the emulator trace).  The signature therefore covers material derived
from the actual APK bytes, and the signer must serve the **exact base.apk
that is installed on the target device** — a wrong or missing APK yields a
server-detectable signature, and attribution silently stays Organic.

The plumbing: `apk_path` (`apks/base.apk`, relative to this folder) lives in
`campaign_data.py` (both campaigns) and `apps.json`; both runners resolve it
against the adj8 folder and read it **once** at startup (~182 MB), then pass
`apk_path=`/`apk_bytes=` into `mint_adj8` whenever the signer build accepts
them (probed via `inspect`, skipped gracefully on older builds).

Replay proof: `cap/replay_device.py` + `cap/device_capture_adj8.log`.

## The LSPosed oracle (adj8/module)

adj9/module's signing oracle (com.adj9oracle) was extended for this app:
- Hook.java: PKG4 = "xyz.be.customer"; record() now mirrors captures to
  logcat in 700-char chunks (the app cannot write /data/local/tmp without
  root; /data/data/<pkg>/files/adj9_capture.log holds the full copy but is
  not readable without root).
- Rebuilt (same package + debug keystore -> adb install -r keeps LSPosed
  state) and installed. Scope: LSPosed manager (via the "LSPosed loaded"
  notification) -> adj9 oracle -> be (xyz.be.customer) ticked.
- The 5.x class hooks (d3/u2/o3) don't exist in the 3.67 signer and fail
  harmlessly; the live hooks are Signer.sign(Context,Map,Map,Map) and the
  JCA layer. Device capture: cap/device_capture_adj8.log.
- Cross-validations from the device: on-device SHA-1 of the APK cert =
  07e6d507...4550 (matches our cert_sha1); a genuine device signature
  verifies under the DK38 tag law and its header matches the bionic seed law
  (seed = signing second) — cap/device_blob_*.hex.

## Python 2.7 build + AutoLabs-format config (2026-10-03)

The backend runs on Python 2.7, so the whole pipeline exists twice:

| file | what it is |
|---|---|
| `campaign_data.py` | campaign config in the AutoLabs backend's shape (nested `adjust` block with app_token/sdk/adj_port/server, `cert_sha1` + `adj_verification` at top level, `retention` table, `tracker: adjust`). Holds both the team's Pentry campaign verbatim as reference and our `customer` entry. 2/3-compatible. |
| `device_data.py` | the DEVICE DATA blob in their nested shape (kernel/locale/ram/display_metrics/build_prop/fingerprint/...), populated from the connected moto g42, plus `device_to_params()` — the translation into Adjust's wire fields (screen_density bucketing from density_dpi, hardware_name = SoC, mcc/mnc stripped, connectivity_type from network). |
| `run_install_py27.py` | the funnel on 2.7 (httplib/urlparse/gzip/HTMLParser compat, `utcfromtimestamp` timestamps). |
| `adj8_pure_py27.py` | the signer on 2.7, generated by `make_py27_adj8.py` from `adj8_pure.py`. |
| `make_py27_adj8.py` | the generator (the transforms: to_bytes→struct.pack, bytes()/_hex()/_b() shims, zero-fills, perf_counter, unicorn mem_write shim). |

Verified on this machine's real Python 2.7.18 (unicorn 2.1.4):
- `py -2.7 adj8_pure_py27.py --selftest` → **OK**: tag law, header law, and a full
  mint whose header matches the golden capture and whose Authorization header is
  byte-identical to the py3 output (39 s).
- `py -2.7 run_install_py27.py --dry-run` → **44 fields, 176 B**, signs cleanly.

Note `print(..., flush=True)` is py3-only; the py27 runner uses a `say()` helper.

## CTIT is real but was not the blocker here

The genuine booking in `be_ct_logs_3oct_pxl.chls` (network Dinos_Dynamic_Partner,
adgroup NN102_DNGT, tracker 244zf3j7) had click_time 12:03:09 → installed_at
12:03:57 = **CTIT ~48 s**, session sent 12:04:09.  Our 14 s was below that, so
`install_after` is now 48 in the config.  Re-tested: still Organic, so CTIT is a
real constraint (the team's penti run booked Organic at 9.96 s) but not the cause
here.  Also ruled out by experiment: reporting the phone's REAL GAID with a
device-matched click (still Organic).

Remaining difference vs the booking capture: that run came through an **oxylabs
residential proxy** (TR, 149.88.106.109) with country=AE in the body; our runs
go out from a Spectranet ISP IP (180.151.14.234, Noida IN).  Next experiment is
to run one click+install through a residential proxy.
