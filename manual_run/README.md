# manual_run

Register a click, report an install, read the attribution — offline, no device.

```
python -u run_install.py --dry-run     # check the config, send nothing
python -u run_install.py               # real run
```

## Commands

| command | what it does |
|---|---|
| `--app NAME` | which campaign to sign for (have: penti, creditsea, declic) |
| `--dry-run` | signs and shows everything, sends **nothing** |
| `--show-config` | print the campaign and device, then exit |
| `--list` | list the campaigns in `apps.json` |
| `--link URL` | override the campaign click link |
| `--set KEY=VALUE` | override any campaign value, repeatable |
| `--device NAME` | use a different `device_data.json` |
| `--device-set KEY=VALUE` | override any device value, repeatable |
| `--no-click` | skip the click, session only |

```
python -u run_install.py --app penti
python -u run_install.py --app creditsea --dry-run
```

`--set` values may be a comma list (`head_phase=0x2b,0x48`), JSON (`[0x2b]`),
an int, a bool, or plain text.

## Files

| file | what it is |
|---|---|
| `run_install.py` | the runner |
| `apps.json` | one campaign per app, keyed by name |
| `adj9_signature.py` | the whole adj9 signature, self-contained |
| `device_data.json` | the device profile |
| `probe_app.py` | reads `cert_sha1` + `head_phase` out of a real signature |

Add a new app by dropping an entry into `apps.json` — nothing in the code
changes.

## The signing API

```python
S.configure_app(campaign)                        # which app we sign for
fields = S.build_session_request(...)            # fields for one API call
blob,  = S.sign_request(fields, "session")       # fields -> 192-byte envelope
header = S.authorization_header(blob)            # envelope -> Authorization
```

`build_click_request` and `build_attribution_request` sit alongside.

## Campaign fields (apps.json)

- `app_token`, `package_name` — identity
- `cert_sha1` — descriptor #9, the SHA-1 of this app's APK signing cert
- `head_phase` — **the d0 head selectors, per app, and the dangerous one**:
  send the wrong value and the server still answers HTTP 200 with a real
  adid, so it fails silently.  Known: penti `["0x2b","0x48"]`,
  creditsea and declic `["0x2b"]`.  `probe_app.py` reads it from a real
  signature.
- `sdk_version` — `5.7.0` or `5.8.0`, picks the claim law
- `client_sdk` — the signed claim; Flutter apps use a composite like
  `flutter5.8.0@android5.8.0`
- `click_link` — the tracker URL; `{gaid}` is substituted
- `gap_seconds`, `poll_delays` — click→install delay, and poll offsets

## device_data.json

`api_level`, `os_version`, `device_name`, `device_manufacturer`,
`hardware_name`, `os_build`, `app_version`, `language`, `country`,
`display_width/height`, `screen_density`, `timezone`, ...

Handled for you, so never put these on the wire yourself:
- `mcc` / `mnc` are **stripped** — genuine bodies carry neither, even on SIM.
- `timezone` is local metadata, never sent.
- `screen_density` uses **Adjust's** vocabulary (`high`), not the device's
  `density_dpi` string (`xxhdpi`).
- `hardware_name` is the SoC (`qcom`), not the codename.
- `enqueue_size / first_error / last_error / retry_count / wait_time /
  wait_total` are **session-only**, dropped from the click body.
  Genuine sets: session 44 fields, click 48.

## Adding an app

Add an entry to `apps.json`:

1. `cert_sha1` — `adj9/rev/cert_verify.py <apk>`, or `probe_app.py <blob>`
2. `app_token` — may be runtime config and absent from the APK
3. `sdk_version` + `client_sdk` — from a signing map in a capture
4. `head_phase` — `probe_app.py <base64-blob>` brute-forces it
5. `click_link` — the tracker URL

Then `--app NAME --dry-run` to confirm it signs cleanly before spending a click.

## Speed

A signature is ~12 s (session) / ~20 s (click): the FinEx VM is ~10M
interpreted steps in pure Python.  A network round trip is under a second, so
the VM is the whole cost.  Requests are signed one at a time, immediately
before each is sent — threads measured 0.89x because the GIL serialises them.
