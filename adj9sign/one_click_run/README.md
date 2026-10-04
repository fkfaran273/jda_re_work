# one_click_run — the adj9 one-click package

Two files do everything, for ANY adj9-signed app:

| file | what it is |
|---|---|
| `adj9_signer.py` | the COMPLETE signature maker in closed form — the whole adj9 law (header, region, claims, block, whitening, digest) in one stdlib-only file. **No VM, no capstone, ~3 ms per signing** (the old VM took 15–25 s). 48 KB / 829 lines, fully self-contained: constants in PART 0, one algorithm per part, T/F/PI/K256 generated, KB/IV2/K stored as the native's own values, test vectors embedded. | | |
| `adj9_funnel.py` | the runner — click → /session → /sdk_click → /attribution → verdict, fully JSON-driven, fresh GAID + android_uuid every run. |

## Run

```
python adj9_signer.py --selftest   # law + 9 genuine captures minted byte-exact (~0.1 s)
python adj9_funnel.py              # one complete conversion attempt (~30 s)
```

## Swap apps = swap JSONs

`adj9_funnel.py` reads `campaign_data.json` + `device_data.json` from this
directory. Nothing else is app-specific. `campaign_data_creditsea.json` is the
second app's config; `cp campaign_data_creditsea.json campaign_data.json` to
switch.

### campaign_data.json keys

| key | meaning |
|---|---|
| `cert_sha1` | **the only per-app secret in the whole law** — the APK cert SHA-1 (descriptor #9) |
| `app_token`, `package_name` | the app's Adjust identity |
| `client_sdk` | the Client-SDK header AND the claims' client_sdk (Flutter apps: the composite, e.g. `flutter5.8.0@android5.8.0`) |
| `adj_signing_id`, `headers_id`, `native_version`, `adj_verification` | the pinned constants (1500000 / 10 / 5.0.0 / KlcAG2…) |
| `click_link` | the tracker link; `{gaid}` is replaced everywhere (incl. callbacks) |
| `pre_click_link` | *optional* affiliate hop: GET it first, take its Location as the tracker link (proven creditsea path: mobpine → go.link) |
| `gaid_params` | params bound onto the tracker link after the pre-click hop (default `adj_gps_adid`, `adj_idfa`, `adj_click_id`; appended unconditionally — last duplicate wins — because affiliate templates carry them EMPTY) |
| `installed_days_ago`, `updated_days_ago` | the install story (default 7/2) |
| `keep_install_story_in_session` | true → /session and /sdk_click keep the days-ago story (proven creditsea path); false → they override installed_at/updated_at to t_click+14s (proven penti path) |

### device_data.json keys

Any device-info dump: `device_name`, `device_manufacturer`, `device_type`,
`api_level`, `os_version`, `os_build`, `hardware_name`, `cpu_type`,
`display_width`, `display_height`, `screen_density`, `screen_format`,
`screen_size`, `language`, `country`, `timezone`, `app_version`,
`package_name`.

## The law (one paragraph)

`blob(192) = header(16) || whiten(record(144), header) || digest(32)`.
header = bionic srand(second) pair-XOR; record = tags + head16 (d0 selectors
over the seed S) + BE32(S) + D9(cert SHA-1) + BLOCK + SHA256("") + consts;
BLOCK = SHA-256 with custom IV2 `eba2c435…` over D9‖00 08‖head16‖LE32(S)‖
SHA256("")‖01‖00*16‖claims; whitening = 14-round SPN (S-box T, keys KB^0x55,
perm PI, GF(2) mix F), CBC from the header; digest = two-pass SHA-256 MAC with
hardcoded K `690f6094…` (pads hashed twice).  Claims = one presence-filtered
law for both SDK 5.7.0 and 5.8.0.  Full details in the module docstring.

## Provenance

- Self-test vectors: 9 genuine device captures (3 creditsea SDK-5.8.0 +
  6 penti SDK-5.7.0 wins) frozen INSIDE `adj9_signer.py` — the file is
  complete on its own, zero external resources, zero file reads.
- Rebuild the signer from the source-of-truth law: `python _build/_build_one_click.py`
  (splices `adj9/rev/algo_practice/pure_signer/pure_sign.py` + `_build/_header.py`
  + `_build/_footer.py`).
- `archive/` holds the previous VM-based signer (`adj9_signer_vm.py`, 546 KB)
  and the funnel that proved penti non-organic with it.
- Conversion proofs: `funnel_pure_run1.log` (penti, NON-ORGANIC, first run of
  the pure signer) and `penti_nonorganic_proof.log` (VM era).

## Operational notes (fraud suite)

- NEVER reuse a GAID across runs (the funnel generates fresh ones itself).
- Space conversions out per tracker/IP: this session, ~10 creditsea clicks in
  15 minutes made EVEN THE PROVEN script return Organic (A/B-tested 20:15 IST
  vs the morning's 2/2 Tarsan1 conversions). Wait 30–60 min per tracker when
  testing repeatedly.
- `installed_at` after vs before the click: both stories have converted (penti
  accepts either; creditsea's proven morning runs used the 9-days-ago story).
  Configurable per app via the JSON keys above.
