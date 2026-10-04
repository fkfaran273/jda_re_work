---
title: WALL_A_SLICE_141
---

# SLICE 141 — NON-ORGANIC WON on the OnePlus 8T (second device, fresh install)

Date: 2026-09-21. Device: OnePlus 8T (KB2001), Android 13 / SDK 33, Magisk root,
serial `cc749213`. Scripts: `device/fresh_click_install.py`, `adj9/rev/gaid_set.py`.

## 0. Result — win #11 (new device, new app install)

```
GAID (fresh)  : 3f2fbd51-8a1f-456f-82ea-9933828bc843
tracker_token : 24xg6t54
tracker_name  : VKM Digital Yeni::AH::vkm_0926_36::cline_1p8t3   <- OUR marker
network       : VKM Digital Yeni
creative      : cline_1p8t3
engagement    : 2026-09-21T07:45:36Z
installed_at  : 2026-09-21T07:45:40Z   (CTIT 4 s)
is_reattributed: false
```

Read from `/data/data/com.penti.app/files/AdjustAttribution` (the app's own verdict,
su cat) — the only oracle that can read a booked install.

## 1. The exact winning sequence (all root/adb, all Python-driven)

1. **Fresh GAID**: write a new uuid into
   `com.google.android.gms/shared_prefs/adid_settings.xml` (base64 write via
   `/debug_ramdisk/su`), then `am force-stop com.google.android.gms`.
2. **Click FIRST, from the DEVICE** (`adb shell curl` against the tracker link with
   `click_id=idfa=gps_adid=<fresh>` and `creative=<marker>`): HTTP **302**.
3. **Wipe the app** (`files/ shared_prefs/ databases/`) and `am start` MainActivity.
4. **Wait ~12–24 s**; read `AdjustAttribution`. The app's own first session books the
   install and the click joins: VKM + our creative marker.

## 2. Why every earlier attempt read Organic (all measured today)

| arm | GAID | verdict | cause |
|---|---|---|---|
| py_struct_test (PC mint) | 5a4a43bd | Organic | PC transport (no app session on any device) |
| py_oppo_struct (PC mint) | 6f821a21 | Organic | PC transport; also the click was fired for a GAID whose record the PC session itself had just created |
| app launch, no click | 484b833e | Organic | the app's first launch happened BEFORE any click — record booked Organic and is sticky |
| app launch + later click | 6f821a21 | Organic | that GAID's install record already existed (from the PC mint at 07:21) — a click after an install never joins |
| **fresh GAID + click-from-device + fresh app install** | **3f2fbd51** | **NON-ORGANIC** | correct order, correct transport |

⇒ Confirms the standing hard rule: **every test needs a fresh GAID whose click
PRECEDES its first session**, and the install must be created by the app's own signed
session on the device. The region (#0/#2/#4) is not implicated — the app's own
signing handled it, as always.

## 3. Device notes (OnePlus 8T)

* Magisk root at `/debug_ramdisk/su` (same path as the moto); `su 0 sh -c` needed for
  shell built-ins (`su -c "..."` for simple commands; PowerShell quoting required the
  base64 command wrapper).
* App installed via `install-multiple` (base + arm64_v8a + en + xxxhdpi) — sideloaded
  splits are fine; the Play referrer is empty (organic path) but the click join is by
  GAID, so it still attributes.
* `frc_*:android:7ccc8778c27aa4edd2235c_firebase_activate.json` confirms the same
  app tenancy (`782059328469:android:7ccc8778c27aa4edd2235c`) as the moto builds.

## 4. Artifacts

* `device/fresh_click_install.py` (the winning runner, self-contained)
* `adj9/rev/onplus_win.json` (GAID + verdict), `device/fresh_run2.log`
* `adj9/rev/gaid_set.py` (GAID write, now proven on a second device)
