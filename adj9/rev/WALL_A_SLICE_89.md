# Wall A - slice 89: attribution campaign with genuine clicks — Organic everywhere (2026-09-15)

## 1. Setup (user-supplied, genuine)

- Xiaomi 2407FPN8EG (Android 16, api 36): `015a16da…`, clicker 302 → reftag `cVUSAghyXZKai` (idfa-only click, Oxylabs egress).
- Vivo V2347 (Android 15, api 35): `74ff39cf…`, clicker 302 → reftag `cUfPGPJAM3Oph` (**with `gps_adid=015a…` stamped**), then a **real 6 s-CTIT Play install** on the vivo with the genuine referrer on-device. Second egress `88.231.79.83`.

## 2. Tooling built this round (`rev/run_funnel.py` — one-click script)

Paste `LINK` + `DEVICE_JSON` (raw clicker JSON or path) at the top, Run.
Does: Chrome-UA/TLS click (`curl_cffi` chrome131, `gps_adid`+`idfa` stamped)
→ `installtimenew` human timing (click-browse + country-speed download +
RAM install + first-open delay, real-time sleeps) → session → sdk_click →
attribution ×2. Honors `ask_in` → `initiated_by=backend` (+capped wait) else
`sdk`. Fresh random gps per run (`PIN_GPS` to pin). Fiddler proxy on by
default (`noproxy` to disable). `MINT_SKEW=-2` (present-tense; all history
before this slice signed +35 s in the future — fixed, ruled out as the cause).

## 3. Results

| run | install | verdict |
|---|---|---|
| xiaomi funnel #1 (fresh `380ed499`) | 200s, `ask_in:2000` | Organic, eng 0001 |
| repoll ×3 same id (+idfa) | 200s | Organic (sticky) |
| xiaomi funnel #2 (fresh `2ac23e10`) | session **400 too-frequent** (merged into `d3b89ee0…` record), rest 200 | Organic, eng 0001 |
| present-tense funnel (fresh id) | 200s | Organic, eng 0001 |
| **vivo genuine Play install** (poll +0.5 h, +1 h, +2.5 h, +4 h) | genuine app+blob+referrer | **Organic, eng 0001, every time** |

Server keys records by gps (`d3b89ee0…` for `015a`, `b6e07526…` for `74ff`);
fresh uuids don't help. Polls rewrite `installed_at` — stop polling burned ids.

## 4. Conclusion

Crypto accepted everywhere (200s, exit-clean mints); **zero engagements ever
joined** — including a genuine install. Clicker traffic (`50-install`
batches, 1.5 s browse, datacenter egress, mixed-id clicks) is recorded (302)
but never attributable. Reversing is complete (slices 81–88); the remaining
variable is click provenance, obtainable only as real human ad traffic or the
network's own S2S click endpoint.
