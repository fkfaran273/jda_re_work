# Wall A — slice 19: fresh device capture — complete tuple, signer unchanged (2026-09-11)

User-approved flip (Vector off, LSPosed on) + reboot + deterministic trigger
(`rm AdjustIoActivityState`, force-stop, launch). Device back clean
(`boot_completed=1`, `lspd` pid 933). Oracle alive: pulled 6.6 MB
(`adj9_fresh_utc.mlog`, 11,021 blocks: 36 signings + 12 probe runs + full JCA).

## Golden fresh event (ts 1789123783xxx, `golden_fresh.json`)

| piece | ts | value (head) |
|---|---|---|
| canonical (d3.a HMAC input) | …3207 | 1288 chars, `{gps_adid_attempt=1, api_level=31, … app_version=3.13.9 …` |
| adj_verification | …3200 | `KlcAG2cbAAsKSl1KVi0FGi…` (const, again) |
| nsign_in | …3224 | `arg3(H)=81e9aa14e975a3d11feecebaddd2893ff5f81eb4bc252525e16b4c6752f8dede` (32 B), `arg4=31` |
| nsign | …3900 | 192 B `4999f1bf…` |
| sign_input | …3900 | 50-field map |
| authorization_header | …3900 | full 6-field header |

Pipeline order confirmed live: `mac_doFinal(H) → nsign_in(arg3=H) → nsign(blob)`.

## Verification on the fresh blob

- **Header law TRUE** (`make_header(sec±2)`): the model survives the app
  update untouched.
- **Signer UNCHANGED**: `algorithm="adj9"`, `1500000/10/5.0.0` — app went
  3.12.1 → **3.13.9**, signer still 5.0.0. All slices stand; version notes
  now carry "app 3.13.9" for fresh captures.
- Adjacent `mac_doFinal` (…1468/539, `268e18db…`) = a prior signing's H in
  the same launch — per-call HMACs differ, as required.

## Yield for R4

First-ever **fully paired live tuple**: canonical + map + H + level + blob
+ header + second, one event, plus 35 siblings and 12 fresh controlled
probe runs (same-device, current app). Java side is now completely
constrained; remaining unknowns are exactly the native-only set (#0 layout,
#2/#3/#6/#7/#8/#10, ns stamps) per slices 10–11.

## Device state left

Flip still in place (Vector DISABLED, LSPosed ENABLED, oracle alive).
Revert = `rm vector/disable` + `touch lsposed/disable` + reboot (restores
the hardening setup found on arrival). Recommend reverting unless another
capture run is wanted — say the word either way.
