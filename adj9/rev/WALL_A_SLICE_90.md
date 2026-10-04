# Wall A — slice 90: the verdict is **signature-bound**; crafted polls cannot read it (2026-09-15)

> Composes with `WALL_A_SLICE_89.md` (genuine clicks, `run_funnel.py`, "Organic
> everywhere"). Slice 89 measured the verdict with **crafted** polls; this slice
> shows that a crafted poll can never observe non-organic — even on a record that
> is provably non-organic. So slice 89's "zero engagements ever joined" is
> unsupported for the farm devices: it is a **measurement** result, not an
> attribution result.

## 0. TL;DR

* Matched pair, same gps + **same `android_uuid`** + same minute: the device's own
  signature → `24pxw9rl` **VKM (non-organic)**; our crafted signature → `wy7261z`
  **Organic**. Only the signature differs. (`dev_ab.py`)
* **Booking oracle:** byte-exact genuine request → `400 {"ask_in":7200000}` (the
  *booked* path); **any** change — 1 bit in the 16-B header, 1 bit in the body,
  our crafted body, a fresh auid, or retimed `created_at`/`sent_at` — → `200` +
  **Organic** (*unbooked* path). (`sig_probe.py`, `probe3.py`, `retime_test.py`)
* Therefore: **`200` + Organic means "not booked", not "not attributed".** Every
  crafted measurement in this campaign (slices 81–89) answers the *unbooked*
  question.
* Eliminated by direct test: identity/auid, request params (22/22 identical to
  the genuine call), UA + `Client-SDK` (dex-verified `android5.7.0`), egress IP
  (same as the device), body-stamp timezone, a **captured genuine `#0`** and a
  **captured genuine `H`**. Remaining untested: `#2` (1 dw) and `#8` (4 dw).

## 1. The matched pair (is it the signature?)

`dev_ab.py` — wipe `AdjustIoActivityState`/`AdjustAttribution`, force-stop,
relaunch (documented mint-on-demand), read the device's own verdict, then ask the
same question with our maker, seconds later:

```
[pre]      auid=41ca78c9-f652-4555-a546-dbe7999efbec   stored=24pxw9rl (VKM)
           wipe + relaunch  ->  fresh install
[post+12s] auid=7aeed4a8-5f4b-43e6-b204-0869a1f8594a   stored=24pxw9rl (VKM)
           {"tracker_token":"24pxw9rl",
            "tracker_name":"VKM Digital Yeni::AH::vkm_0926_36::penti_generic",
            "network":"VKM Digital Yeni","campaign":"AH",
            "engagement_time":"2026-09-14T10:25:58Z",
            "installed_at":"2026-09-14T12:23:08Z"}
[crafted, same gps + same auid]  200 wy7261z / Organic / eng=0001-01-01T00:00:00Z
```

The identical record answered **VKM** to the device and **Organic** to us.
(`dev_ab_result.json`, `dev_ab.log`)

## 2. The booking oracle

| variant (same URL, same claim set) | blob | HTTP | reading |
|---|---|---|---|
| A verbatim genuine (×6, interleaved) | genuine | **400 ask_in:7200000** | **booked** |
| E genuine hdr + genuine body | genuine | 400 | booked |
| C crafted body | ours | 200 | unbooked → Organic |
| D genuine hdr + crafted body | hybrid | 200 | unbooked |
| F genuine + 1 bit body[0] | genuine±1 | 200 | unbooked |
| G genuine + 1 bit header[0] | genuine±1 | 200 | unbooked |
| B genuine + fresh auid | genuine | 200 | unbooked |
| retimed genuine (`created_at`/`sent_at` → now) | genuine | 200 | unbooked |

* The gate is **content-exact**: one bit anywhere — header *or* body — or one
  changed request timestamp, drops a genuine signature into the Organic bucket.
  It is not a MAC check (the 16-B header carries no integrity); it is
  whole-artefact consistency with the request.
* `probe3.py` (all 10 genuine units from the wire dump): `400` ⇔ the unit's
  `created_at` is older than the install's last accepted session; the units that
  pass return the record's *current* answer. ⇒ `400` is an ordering/interval
  artefact, not a verdict.

## 3. Consequences (read this before trusting any "Organic" panel)

1. **Never verify attribution with a crafted poll.** A crafted signature is
   *always* unbooked → always Organic, whether or not an engagement was joined.
   Authoritative sources only:
   * on device — `/data/data/com.penti.app/files/AdjustAttribution` (888 B, holds
     the full attribution JSON; `dev_state.py`),
   * the app's own `/attribution` request+response (MITM tap),
   * `logcat`/the SDK's own log.
2. Slice 89's "genuine install still Organic at +0.5/1/2.5/4 h" was measured
   with crafted polls ⇒ inconclusive about engagement. Re-verify from the device.
3. `/session` is a *different* gate: our crafted sessions are accepted (200 +
   adid, records created). "200 on /session" never implied the /attribution gate.
4. A bare signed `/attribution` poll with a fresh auid **creates** an install
   record (`installed_at` = receipt) → Organic. Polls burn identity; don't.
5. What *does* earn non-organic: the moto's record (`2fedfd3d`, gps `d016e7e4`)
   is non-organic with a real campaign engagement (`10:25:58Z`, campaign `AH`,
   `vkm_0926_36`, `penti_generic`), and **two fresh wipe/relaunch cycles today
   each got `24pxw9rl` VKM within ~12 s** — i.e. the genuine-install path works;
   the farm's crafted path never can (it cannot book).

## 4. Remaining slot candidates + the definitive experiment

`#2` (1 dword, `u32 @struct+0x20`, per-signing) and `#8` (4 dwords, runtime
buffer) — everything else was eliminated by direct test. Hypothesis: the body
must be bound to *this* signing under the TEE-keyed HMAC path, which is exactly
the anti-forgery property the design exists for.

Definitive: one Frida capture of the **full descriptor set for a single
`/attribution` signing** (`device/mkdump.js` hooks the 11 `mkdesc` sites;
`device/get0.js` already dumps the 144-B `#0`; hook `nSign` for arg3 = `H`), then

1. rebuild with `fin_vm2.FinEx` → must be byte-identical to the wire blob;
2. bisect: replace one slot at a time (`#0`, `#2`, `#4/H`, `#8`) with
   zeros/random and read the oracle → identifies exactly which slot(s) the server
   requires. Either outcome is a *measured* answer.

## 5. Files added this slice (`adj9/rev/`)

`dev_state.py` (device state reader), `dev_attr_test.py` (auid variant test),
`dev_ab.py` (the matched pair), `sig_probe.py` (booking oracle A–G),
`probe2.py`/`probe3.py` (genuine-corpus replays), `retime_test.py`,
`stamp_test.py`, `slot_test.py`, `parse_devlog.py`, `device_funnel.py`
(device-profile funnel + CONNECT proxy support), `click_bind_chain.py`; artefacts
`dev_ab_result.json`, `sig_probe_result.json`, `probe3_result.json`,
`retime_test_result.json`, `stamp_test_result.json`, `slot_test_result.json`,
`dev_attr_test_result.json`, `click_bind_result.json`.

