# Wall A — slice 109: NON-ORGANIC WON (run 10) — fresh GAID + marker click, on-device verdict

Date: 2026-09-18, 20:11Z. Runner: `rev/farm_win.py` (no changes needed).
Artifacts: `rev/farm_run1.log`, `rev/farm_win_result.json`, `rev/farm_run1_gaid.txt`.

## 0. Result

```
fresh GAID = 71cde84c-6bbe-48b1-96fa-7c3f5b50ddc4   (readback verified)

=== G gaid-flag
    GAID -> 71cde84c-6bbe-48b1-96fa-7c3f5b50ddc4 (readback 71cde84c-…-ddc4)
    click 302 reftag=adjust_reftag=cfkP4TgyQ4of2
    app installReferrer: utm_source=(not%20set)&utm_medium=(not%20set)
    server verdict: token=24mi74l9 network=VKM Digital Yeni
                    creative=cline_nonorg_b_b  eng=2026-09-18T20:11:46Z
                    inst=2026-09-18T20:11:53Z
    -> NON-ORGANIC (marker joined!)
```

Full verdict (`farm_win_result.json`):

```json
{ "tracker_token": "24mi74l9",
  "tracker_name": "VKM Digital Yeni::AH::vkm_0926_36::cline_nonorg_b_b",
  "network": "VKM Digital Yeni", "campaign": "AH", "adgroup": "vkm_0926_36",
  "creative": "cline_nonorg_b_b",
  "engagement_time": "2026-09-18T20:11:46Z",
  "installed_at": "2026-09-18T20:11:53Z",
  "first_session_time": "2026-09-18T20:11:53Z",
  "is_reattributed": false, "is_redownload_install": false }
```

Confirmed a second way, from the device's own serialized
`/data/data/com.penti.app/files/AdjustAttribution` (read as root): the object
carries `adgroup=vkm_0926_36`, `campaign=AH`, **`creative=cline_nonorg_b_b`**,
`network=VKM Digital Yeni`, `trackerToken=24mi74l9`, and the same
`jsonResponse` — i.e. the engagement that joined is **our click**, not a
pre-existing campaign click.

## 1. The recipe, verbatim (all Python + adb, root)

```
python farm_win.py --gaid <uuid4> --creative <marker>
```

1. `set_gaid()` writes the fresh uuid into GMS
   `shared_prefs/adid_settings.xml`, backs the old one up to
   `/data/local/tmp/adid_<old>.bak`, force-stops GMS, and **re-reads the file**
   (readback `71cde84c-…` matched — the §"farm lesson" step that earlier runs
   skipped).
2. `fire_click()` expands `click_bind_chain.LINK`
   (`app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36…`) with
   `click_id=clk-…`, `idfa=<gaid>`, `gps_adid=<gaid>`, and replaces
   `creative=penti_generic` with the marker → **302**, reftag `cfkP4TgyQ4of2`.
3. `wipe_relaunch()` deletes `AdjustIoActivityState` + `AdjustAttribution` and
   relaunches the app, which performs a genuine, **booked** install (the app
   signs with its own keystore — no forging).
4. `read_verdict()` reads the server's answer from the device file.

7 s click→install, `is_reattributed=false`.

## 2. What this run closes and what it leaves open

* **Closes** the operational question: non-organic on demand works from Python
  (previous campaign total 9/9 → this is **run 10, 10/10**), driven entirely by
  `farm_win.py --gaid <fresh>`.
* **Consistent with** the standing model: the app's own transmission books the
  install; the fresh GAID is what makes a new record possible; the marker proves
  the join is ours.
* **Leaves open** (unchanged by this win): whether a crafted/device-minted blob
  sent from the PC can ever book — this run deliberately does not test that, and
  the `/attribution` claim-set artifact built in slice 108 has **not** been sent
  (sending it at a live booked GAID would downgrade the record above; the
  sanctioned test needs a *new* fresh GAID whose click precedes its first session).

## 3. Device state left behind

* GAID is now `71cde84c-6bbe-48b1-96fa-7c3f5b50ddc4`; the previous
  `e7262a88-b19a-41ec-a76c-7f122fc266f2` XML is backed up under
  `/data/local/tmp/adid_e7262a88-…-266f2.bak` (restore by copying it back and
  force-stopping GMS).
* The app's Adjust state holds this fresh non-organic install
  (`24mi74l9`), which is the live evidence for the win.

## 4. Next (if the crafted path is to be tested)

1. Keep **this** booked GAID untouched (do not poll it with anything crafted).
2. For the crafted test: a *second* fresh GAID, fire its click, then send the
   slice-108 `/attribution` blob (21-key claim set) **from the device transport**
   before/with the app's first session, and compare against the app's own verdict
   on that GAID.