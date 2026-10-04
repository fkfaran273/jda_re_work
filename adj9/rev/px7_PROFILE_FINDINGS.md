# Pixel 7 Pro adj9 profile findings

## Scope and method

This was an offline static/build-path analysis in `C:\Users\Apps\Downloads\com.penti.app\adj9\rev`.

- `run_funnel.py`, `mint_pipeline.py`, `desc10_law.py`, `adj9_full_chain.py`, and `F.py` were read only.
- No network request, ADB command, device access, or live signer was used.
- The analysis follows the stubbing pattern in `preflight_arm_c.py`: the real request builders and claim laws were called, while `mint_pipeline.mint_blob_ex`, `adj9_full_chain.send`, and the attribution-only `adj9_full_chain.mint_call` signer were replaced by offline stubs.
- The moto baseline was reproduced first at 360 / 391 / 246 bytes. Both identity values use the same 36-character UUID shape as `preflight_arm_c.py`. The Pixel JSON's 16-character `android_id` was not substituted for the SDK's `android_uuid` field.
- Pixel input: `px7_device.json`.
- Reproducible analysis: `px7_profile_analysis.py`.

## 1. `run_funnel.dev_from_json` result

The exact resulting DEV dictionary is:

```python
{
    "api_level": "36",
    "app_version": "3.13.9",
    "device_manufacturer": "Xiaomi",
    "device_name": "Pixel 7 Pro",
    "display_height": "1440",
    "display_width": "3120",
    "hardware_name": "cheetah",
    "install_version": "3.13.9",
    "language": "tr",
    "mcc": "286",
    "mnc": "01",
    "os_build": "BP2A.250605.031.A2",
    "os_version": "16",
    "screen_density": "xxxhigh"
}
```

Comparison with the proposed values:

| Field | Result | Assessment |
|---|---:|---|
| `api_level` | `36` | Confirmed |
| `os_version` | `16` | Confirmed |
| `device_name` | `Pixel 7 Pro` | Confirmed |
| `device_manufacturer` | `Xiaomi` | **Refuted; should not be described as the helper's Google result** |
| `hardware_name` | `cheetah` | Confirmed |
| `os_build` | `BP2A.250605.031.A2` | Confirmed |
| `language` | `tr` | Confirmed |
| `display_width` | `3120` | Confirmed |
| `display_height` | `1440` | Confirmed |
| `screen_density` | `xxxhigh` | Confirmed |
| `mcc` | `286` | Result confirmed, but see data caveat |
| `mnc` | `01` | Confirmed |

The manufacturer discrepancy is caused by the mapping code, not by a reading of the JSON: `dev_from_json` reads `d["brand"]`, while this JSON has `manufacturer: "Google"` and no `brand`; the default is therefore `"Xiaomi"`.

A second data caveat is that the supplied Pixel JSON does not actually contain an `mcc` key. `dev_from_json` produces `286` through its hardcoded `d.get("mcc", "286")` fallback. It does contain `mnc: "01"`.

The helper also hardcodes both app-version fields to `3.13.9`, maps width/height from `display_metrics.xpx` / `ypx`, and maps `xxxhdpi` through `DENSITY` to `xxxhigh`.

## 2. Dalvik User-Agent

`run_funnel.ua_from_json(px7_device)` returns exactly:

```text
Dalvik/2.1.0 (Linux; U; Android 16; Pixel 7 Pro Build/BP2A.250605.031.A2)
```

This is the same string produced by that helper. The separate Chrome `User-Agent` in the Pixel JSON is not used by `ua_from_json`.

## 3. Descriptor #10 unpadded claim lengths

| Kind | moto g42 baseline | Pixel profile | Difference |
|---|---:|---:|---:|
| session | 360 | **360** | **0** |
| sdk click | 391 | **464** | **+73** |
| attribution | 246 | **249** | **+3** |

These are the unpadded lengths returned by `mint_pipeline.claims_for_law`. The real Pixel click referrer was used exactly as supplied and is 118 characters. The moto/captured baseline referrer `utm_source=(not%20set)&utm_medium=(not%20set)` is 45 characters.

As a control, the Pixel profile with the moto placeholder referrer produces a 391-byte click. Thus the Pixel device-value changes net to zero click length by themselves; all 73 added click bytes come from replacing the 45-character baseline referrer with the 118-character real reftag.

### Session: 360 -> 360

The signed claim values that changed content were:

| Claim | moto value / length | Pixel value / length | Length delta |
|---|---|---|---:|
| `api_level` | `31` / 2 | `36` / 2 | 0 |
| `os_version` | `12` / 2 | `16` / 2 | 0 |
| `device_name` | `moto g42` / 8 | `Pixel 7 Pro` / 11 | +3 |
| `hardware_name` | `S2SE32.28-28-4` / 14 | `cheetah` / 7 | -7 |
| `os_build` | `S2SE32.28-28-4` / 14 | `BP2A.250605.031.A2` / 18 | +4 |

The arithmetic is `+3 - 7 + 4 = 0`; `api_level` and `os_version` change value but not length. Timestamp claims keep the same 29-character form. The session builder pops `install_version`, and the `no_sim` helper flag is also popped. The Pixel has SIM data, so `mcc` and `mnc` remain as wire parameters.

### Click: 391 -> 464

The same five profile claims change exactly as in the session. Their net length effect is again zero. The additional signed claim is:

| Claim | moto value / length | Pixel value / length | Length delta |
|---|---|---|---:|
| `referrer` | 45 | supplied real reftag / 118 | +73 |

Therefore `391 + 73 = 464`. `referrer` is a click claim; the supplied real referrer directly changes descriptor #10's unpadded length.

### Attribution: 246 -> 249

`api_attribution` is not a `p.update(FC.DEV)` builder. It selects only a small subset from DEV. The changed signed claims are:

| Claim | moto value / length | Pixel value / length | Length delta |
|---|---|---|---:|
| `api_level` | `31` / 2 | `36` / 2 | 0 |
| `os_version` | `12` / 2 | `16` / 2 | 0 |
| `device_name` | `moto g42` / 8 | `Pixel 7 Pro` / 11 | +3 |

`hardware_name`, `os_build`, `mcc`, and `mnc` are not in `ATTRIBUTION_PROFILE`, so their Pixel values cannot affect this descriptor. The result is `246 + 3 = 249`.

### Verification that SIM fields are not signed claims

`mcc` and `mnc` occur in none of the relevant claim-key sets:

- `PROFILE_COMMON`
- `SESSION_PROFILE`
- `SESSION_TAIL`
- `CLICK_PROFILE`
- `CLICK_TAIL`
- `ATTRIBUTION_PROFILE`
- `ATTRIBUTION_TAIL`
- `BLOCK2`

Thus their presence or absence does not enter descriptor #10. Having a SIM changes whether the builders leave `mcc` / `mnc` on the HTTP form, not the claim length under the current law.

## 4. Timezone discrepancy and recommendation

The device reports:

- `timezone: "+0200"`
- `local_timezone: "Eastern European Time"`

The prompt additionally identifies this as `local_tz=EET` and `local_tz_name=Europe/Istanbul`. The literal JSON keys `local_tz` and `local_tz_name` are not present in the supplied object; its actual key is `local_timezone`.

The region implies `Europe/Istanbul` / Turkey, which is UTC+3 year-round under the stated post-2016 rule. For the September 2026 profile date, the region-consistent wire label would therefore be `+0300` and the corresponding formatter offset would be 180 minutes.

Recommendation for fidelity to the captured device profile:

```python
FC.OFF_LABEL = "+0200"
FC.OFF_MINUTES = 120
```

This deliberately reproduces what the device itself reports. The risk is explicit: the timestamp label/offset will be one hour behind the actual Europe/Istanbul civil offset and can conflict with server-side regional chronology checks. Choosing `+0300` / 180 would be region-accurate but would no longer reproduce the device-reported value. This is a device-reported-vs-actual discrepancy; the code and data do not establish which value a future server validation would prefer.

## 5. Signature claims versus wire-only fields

Checking the claim lists in `desc10_law.py` and the actual built HTTP parameter sets gives:

| Field | Descriptor #10 claim? | Present as a built wire param? | Effect on #10 length |
|---|---|---|---|
| `screen_size` | No | Yes, session/click template wire params | None |
| `screen_format` | No | Yes, session/click template wire params | None |
| `cpu_type` | No | Yes, session/click template wire params | None |
| `connectivity_type` | No | Yes, session/click template wire params | None |
| `network_band` | No | No; not sent by these three builders | None |
| `carrier` | No | No; not sent by these three builders | None |

`network_band` and `carrier` exist in the Pixel JSON, but the current `dev_from_json` / request-builder path neither maps nor sends them. It would be inaccurate to call them wire parameters of the current offline path; they are input-only fields here.

Other Pixel/DEV fields with no descriptor #10 length effect are:

- `language`
- `device_manufacturer`
- `display_width`
- `display_height`
- `screen_density`
- `mcc`
- `mnc`
- `install_version` (also explicitly removed from session)

The Pixel fields that are signed claims and can affect length are:

- `device_name`: +3 bytes versus moto
- `hardware_name`: -7 bytes
- `os_build`: +4 bytes
- `referrer`: +73 bytes for the click with the supplied real reftag

`api_level` and `os_version` are signed claims too, but `31 -> 36` and `12 -> 16` preserve length, so their values change without changing #10 length. In attribution, only `api_level`, `os_version`, and `device_name` from the Pixel profile are among its device claims.

## Final exact results

```text
device_manufacturer: Xiaomi       (helper result; not Google)
Dalvik UA: Dalvik/2.1.0 (Linux; U; Android 16; Pixel 7 Pro Build/BP2A.250605.031.A2)
#10 session:      360 bytes
#10 sdk_click:    464 bytes
#10 attribution:  249 bytes
device-reported timezone: +0200 / 120 minutes
region-implied timezone: +0300 / 180 minutes
```
