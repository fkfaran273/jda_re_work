# adj9_tool

Standalone Adjust `adj9` (SDK 5.x) signing and API flow for `com.penti.app`.

## Files

| File | Purpose |
|---|---|
| `pentiandroid.py` | The `adjust_v1` path: click the tracker link, then `/session` → `/sdk_click` → `/attribution`, signed locally. |
| `adjust_v1.py` | Adjust SDK 5.7.0 request builder. Signs session/click/attribution with `adj9_signer` in-process. |
| `util.py` | HTTP send, hashing, random-token helpers. |
| `oneclick.py` | Older entry point. Reads the phone, clicks, optionally installs, then sends. |
| `device_probe.py` | Reads real device facts off the phone over adb (screen, build, locale, timezone, ...). |
| `adj9_api.py` | Independent sender for the same three requests; sends over PC or `adb shell curl`. |
| `adj9_signer.py` | Complete signer: header PRNG, region, descriptor #10, VM, `mint_blob`, `auth_header`. |
| `device_profile.json` | Fallback device facts (moto g42) when no phone is connected. |
| `_base_templates.json` | Non-device `S1P` / `S2P` param skeletons. |
| `_scratch/` | Archived experiments and logs. Not needed to run. |

Runtime inputs located outside this folder:

- Python package `capstone` (`pip install capstone`).
- `libsigner.so`, auto-discovered or set with the `ADJ9_LIB` environment variable.
- `adb` on PATH (or in `ANDROID_HOME` / `C:\platform-tools`) if you want the
  script to read the phone or install the app.

## Run

```bash
pip install capstone
python pentiandroid.py
```

That script is three steps: **click the tracker link → send the three calls**.

**The click.** `fire_click` opens `LINK` with the phone's own Chrome UA, does
*not* follow the redirect (it points at `market://`, which urllib cannot fetch),
and pulls the install referrer out of the `Location` header. It handles
`market://details?...&referrer=`, `play.google.com?...&referrer=` and the
App Store `&pt=` form.

**The device.** With `DEVICE_DATA = ""` the script asks the phone over adb and
saves what it found to `device_data.json`. Every value comes off the device, so
the run cannot drift from the phone being tested. It uses the *app-visible*
screen size from `dumpsys window displays` (`app=1080x2237`), not the physical
panel, because that is what the SDK signs. To run as some other phone, paste a
JSON dump into `DEVICE_DATA` or name a file.

**The three calls.** Exactly what the real app sends, in this order:

| # | Call | Method | Params | Signed |
|---|---|---|---|---|
| 1 | `/session` | POST | 43 | adj9 |
| 2 | `/sdk_click` | POST | 47 | adj9 |
| 3 | `/attribution` | HEAD | 22 | adj9 |

There is no `sdk_info`, no `push_token` and no `event_buffering_enabled` —
none appear in the captured traffic. `ask_in` from the `/session` response
decides both the poll delay and `initiated_by` (backend when present).

`GPS_ADID` empty means a **fresh GAID every run**; never reuse one, or Adjust
collapses the installs into a single device. `DRY = True` builds and signs all
three requests without sending them.

## Signing notes

- The VM is seeded with the signing second. `created_at`, `sent_at`, and the region `V` all use that same second. In `adjust_v1` that second is *derived from the `created_at` string that goes on the wire*, not read from the clock at signing time — otherwise the header and the timestamp disagree and the region becomes irreproducible.
- Heads: `session` and `sdk_click` use H4 (`2b 22 25 2e`); `attribution` and re-signs use H5 (`2b 07 22 25 2e`).
- Verified against `../rev/saz_blobs.json`: the 16-byte header is byte-exact
  for all three captured vectors, and descriptor #10 lands on the predicted
  sizes (session 360 B, click 391 B, attribution 246 B). The 176-byte body is
  **not** reproduced. All 37 candidate `V` values inside the created→sent
  window were tested for the attribution vector and **none** reproduces the
  captured body, so `V` selection is not the gap — the FinEx VM execution
  (and/or the region inputs `pid`/`tid`/`head`) is still wrong.
