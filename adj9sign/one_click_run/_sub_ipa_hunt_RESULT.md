# IPA hunt result — Cainiao iOS container (com.cainiao.cnintl4iphone)

Date: 2026-10-01. Scope: local disk only (no network fetch).

## Verdict

**No iOS app container exists on this machine.** Zero hits for `*.ipa`, `*.tipa`,
`*.app` bundles, `Payload/` directories, `.mobileprovision`, `.dSYM`, `.xcarchive`,
`.deb`, `*.decrypted` binaries, or Apple `.p12` signing certs (only mitmproxy CA
certs matched). No sideloading/patching tool is installed either — no Sideloadly,
AltStore/SideStore, TrollStore, Scarlet, ESign, Feather, i4Tools/爱思助手,
checkra1n/palera1n data anywhere (Program Files, Program Files (x86), ProgramData,
AppData all checked).

The only explanation consistent with the artifacts: the "modified IPA" was never
on this Windows box. The iOS work here is **traffic-capture analysis + Python
request replay/signing** (`adj9_signer.py`), and the capture itself is from an
**ios-simulator build** (`{"os_name":"ios-simulator"}`, see
`adj9sign/IOS_VERIFICATION.md`) produced by an external iOS simulator service,
not by a local sideloaded device install.

## What WAS found (Apple/iOS-related)

### Captures (the Cainiao capture is confirmed present)
| Size (bytes) | Path | What it is |
|---|---|---|
| 55,066,175 | `C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz` | The Fiddler capture referenced by the task (30 signed adj9 requests, Cainiao iOS) |
| 5,936,189 | `D:\my_personal_projects\my_code\credcoliosmodd_18aug26_ios11_install.saz` | Other iOS capture (CredCol, iOS 11) |
| 11,868,869 | `D:\my_personal_projects\my_code\credcoliosmodd_18aug26_weblogs.saz` | Other iOS capture (web logs) |
| 9,697,877 | `C:\Users\Apps\Downloads\nike_15sept_install_newapp_recheck_ios11.saz` (+ `.chls` 12,338,055) | Other iOS capture (Nike, iOS 11) |

### Extracted capture data
- `C:\tmp\saz_ios\` — extracted Fiddler SAZ export (`_index.htm` + `raw\NNNN_c.txt/_s.txt/_m.xml`, ~66+ sessions). First session is TLS to `api-adservices.apple.com` — an iOS capture unpacked for analysis.
- `C:\Users\Apps\AppData\Local\Temp\saz_ios\` — **empty** directory.

### iOS replay/signing scripts (not IPA tools)
~150 files named `<app>iosmodd.py` / `<app>iosmodd.pyc` — Python traffic-replay
scripts, one per iOS app analyzed. Locations:
- `D:\my_personal_projects\my_code\` (incl. `credcoliosmodd.py`)
- `D:\my_projects\all_working_scripts\` (incl. `cairinonlinemodd.py`, `matchbookclientiosmodd.py`)
- `D:\my_projects\mayank's scripts\`, `D:\my_projects\sakshi's script\`
- `D:\office_dev_projects\mining_services\` (incl. `polymarkettiosmodd.py`, `skillziosmodd.py`)

### iOS simulator tooling (no IPA inside)
- `C:\Users\Apps\.zcode\cli\plugins\cache\zcode-plugins-official\ios-simulator\0.1.0\` — ZCode plugin (MCP server + skill) for building/running SwiftUI apps in an iOS simulator. Explains the capture's `ios-simulator` os_name. Contains only JS/TS/MD files, no binaries.

### frida (all Android, not iOS)
- `C:\Users\Apps\AppData\Local\frida\State\` — tool state only.
- `C:\Users\Apps\dl_frida.ps1`, `download_frida.ps1` — download `frida-server-17.17.0-android-arm64.xz` (explicitly Android).
- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\bin\frida-server` (53,539,200) and `frida-server16` (53,702,368); copies under `D:\com.penti.app\...`, `D:\Downloads - Copy\...`; `D:\fortress\artifacts\frida\frida-server` (113,499,416); `D:\Downloads - Copy\com.avito.android\frida-server-arm64` (53,539,200).
- All verified by magic bytes: `7f 45 4c 46` = **ELF (Android)**, not Mach-O.

### Minor keyword coincidences (not iOS)
- `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea\sideload_click.json` — Adjust SDK click data, not app sideloading.
- `C:\Users\Apps\AppData\Roaming\JetBrains\PyCharm2026.2\tasks\cairinonlinemodd_py.{contexts,tasks}.zip` (139 / 139 bytes) — PyCharm task metadata for the Android cairino script.
- `...\com.app.frndo\base_decoded\assets\fonts\Feather.ttf`, `pyarrow/pandas feather_*` files — name collisions.
- `C:\Users\Apps\.mitmproxy\mitmproxy-ca{,-cert}.p12` — mitmproxy CA certs.

### The one unexplained large archive
- `C:\Users\Apps\Downloads\Unconfirmed 161953.crdownload` — **819,232,444 bytes**, mtime 2026-09-17 15:33. Magic `52 61 72 21 1a 07 01` = **RAR5**, and 7-Zip reports it as **password/header-encrypted** ("Enter password"), so contents cannot be listed. It is an abandoned Chrome partial download, NOT a zip/IPA (no zip EOCD, no plaintext Payload marker). Cannot be ruled iOS-related, but nothing ties it to iOS.

## Coverage (what was searched and how)

Method: Python `os.walk` with pruning, 3 passes (extensions, name substrings, directory names), plus targeted inspections (zipfile/7z/magic bytes).

Walked:
- `C:\Users\Apps` — 579,523 files, depth 6, with an exception allowing unlimited depth under any dir named `Payload`/`*.app`/`*.dSYM`/`*.xcarchive` or matching ios/ipa keywords.
- `D:\` — 199,781 files, depth 6 (final pass).
- `C:\temp` (9), `C:\tmp` (10,659), `C:\Tools` (2), `C:\Secrets` (3), `C:\Users\Public` (27), `C:\ProgramData` (212, depth 2), `C:\$Recycle.Bin` (92 files — all small `.py`/`.out`/`.pyc`, no IPA-sized items).

Extensions searched: `.ipa .tipa .deb .app (dir+file) .dSYM .mobileprovision .provisionprofile .decrypted .dylib .entitlements .xcarchive .appex .p12 .saz .crdownload`; archives `.zip/.7z/.rar` matched by name keywords.

Name keywords (case-insensitive): cainiao, cairino, cnintl, iosmodd, modd, sideload, altstore, altserver, sidestore, trollstore, esign (word-boundary), feather, 爱思助手， i4tools, checkra1n, palera1n, frida (excl. friday), dumpdecrypted, decrypted, payload, cydia, impactor, theos, ldid, substrate, appsync, itunes, entitle, ipa/ios (word-boundary).

Pruned (as instructed / to keep the scan fast — noted for completeness):
- `node_modules`, `.git`, `__pycache__`, `site-packages`
- `C:\Users\Apps\AppData\Local\{Google, Microsoft, Android, pip, uv, npm-cache, go-build, ms-playwright, JetBrains, D3DSCache}`
- `C:\Users\Apps\Documents\adjust_Apps\penti_android` (known Android folder)
- `C:\Users\Apps\Downloads\com.penti.app` (known Android folder — except its `adj9sign` and `fiddler` subdirs, which were fully scanned)
- Windows junction dirs (`Application Data`, `Local Settings`, `My Documents`, `Temporary Internet Files`, `History`, etc.)
- On D:: `Android`, `flutter`, `jdk17`, `llama.cpp`, `model_training`, `.cache`, `advance_emu`, `$RECYCLE.BIN`, `System Volume Information`
- A big-file sweep (>50 MB, 302 files) was also run to catch IPA-sized files under odd names; all are Android APKs/emulator images/logs/ELF frida-servers/known archives.

Access denied (unscannable): `C:\Users\Apps\Recent` (junction), `D:\System Volume Information`, a few `C:\ProgramData` system subdirs, `C:\$Recycle.Bin\S-1-5-18` (system SID). None plausible IPA locations.

## Where to plug in the IPA

No tooling here consumes an IPA, but if one is provided, drop it in
`C:\Users\Apps\Downloads\` (or `D:\Downloads - Copy\`) with a `.ipa` extension;
a `.zip` must also contain `Payload/<App>.app/`. If it arrives inside the
encrypted RAR (`Unconfirmed 161953.crdownload`), the password is needed first.
