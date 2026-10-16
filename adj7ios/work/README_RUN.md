# adj7 iOS — pure-Python funnel (NON-ORGANIC BOOKED 2026-10-09)

## THE WIN (live, pure Python, iOS)

```
app        com.berain.berain  (Berain Water, App Store id 1298014792)
tracker    20yvzdd5  ->  campaign TMV May_Derby / adgroup NP_SH_Q
verdict    TMV Media / 20fholu3 / TMV Media::TMV May_Derby::NP_SH_Q
engagement 2026-10-09T10:40:47Z   (the click)
adid       4a4bd2c212134f84bfd4a296dcdd977a
```

Flow that booked (28 s total): click (direct Adjust link with `idfa=`) →
session (200, `ask_in 2000`) → tps (202) → sdk_click (200) → attribution
(200, **NON-ORGANIC on the first poll**).

## Files

| file | what |
|---|---|
| `adj7ios_pure.py` | signer, Python 3 — selftest **22/22 byte-exact** |
| `adj7ios_pure_py27.py` | signer, Python 2.7 — selftest **22/22 byte-exact** |
| `run_berain.py` | berain funnel, Python 3 (link hardcoded) |
| `run_berain_py27.py` | berain funnel, Python 2.7 (link hardcoded) |
| `run_install_ios.py` / `run_install_ios_py27.py` | nirio-shaped funnel (both dry-run clean) |
| `last_run_berain.json` | the booked run's record |

py3 and py2.7 mint **byte-identical** blobs (cross-checked on all 5 kinds).

## Run it by hand

```
cd C:\Users\Apps\Downloads\com.penti.app\adj7ios\work

python        run_berain.py            # full live funnel (py3)
python2.7     run_berain_py27.py       # full live funnel (py2.7)
python        run_berain.py --dry-run  # sign only, send nothing
```

The click link is hardcoded in both runners:

```
https://app.adjust.com/20yvzdd5?campaign=TMV+May_Derby&adgroup=NP_SH_Q
    &os_name=ios&idfa=<FRESH PER RUN>&gps_adid=<SAME IDFA>&click_id=<FRESH>
```

Overridable without editing: `FUNNEL_IDFA`, `FUNNEL_CIT`, `FUNNEL_PROXY`,
`FUNNEL_CLICK_URL`, `FUNNEL_REFTAG` (+ `FUNNEL_CLICK_SEC`).

The upstream tracker hop (only redirects for a real browser, so optional):

```
https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52
    &pub_sub_id=1298014792&pub_click_id=<FRESH>&idfa=<IDFA>&gaid=<GAID>
    &app=com.berain.berain&creative=NP_SH_Q
    -> 302 https://app.adjust.com/20yvzdd5?campaign=TMV+May_Derby&adgroup=NP_SH_Q...
    -> 302 https://apps.apple.com/app/id1298014792?mt=8
```

## What made it book (and what didn't)

- The join param on an iOS direct link is **`idfa=`** (same value in the click
  and the session). `sub3=`/`gaid=` are publisher macros, not device matches.
- The winning link carried **no `ip_address=` and no `android_id=`** — the
  earlier failing iOS clicks (hunch) carried a random `ip_address=`, which
  records the click against a different IP than the session. Stripping it did
  not rescue hunch, so the IP alone was not the whole story, but the
  berain-win shape is the one to copy.
- A fresh `idfa` per run, `att_status 3`, CTIT ~20 s, double-ask on Organic.

## hunch iOS is still Organic — and that matches the device

The genuine `hunchdatingiosauto_newapp_1appril2026` capture's own verdict was
`unattr / "No User Consent"` — the hunch iOS tracker does not book that app.
Our `Organic / yuzxv6m` is the same non-paid class (per-app naming), so the
iOS funnel is not at fault there; the tracker is.
