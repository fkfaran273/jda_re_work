# FINAL — non-organic booked fully offline, pure Python (2026-09-29)

**Verdict: GOAL REACHED.** `win_funnel2.py <real_gaid> <android_uuid>` booked a
non-organic attribution end-to-end with zero device participation:

```
attribution 200: {"tracker_token":"24xxe7sm",
                  "tracker_name":"VKM Digital Yeni::AH::vkm_0929::penti_generic",
                  "network":"VKM Digital Yeni","campaign":"AH",
                  "adgroup":"vkm_0929",          <-- OUR invented click adgroup
                  "creative":"penti_generic",
                  "is_reattributed":true}
```

## The winning recipe (win_funnel2.py)

1. **Click** — curl_cffi `chrome131`, `app.adjust.com/1sd1lk6a?campaign=AH&
   adgroup=<ours>&creative=penti_generic&click_id=<gaid>&idfa=<gaid>&gps_adid=<gaid>`
   → 302 + `adjust_reftag=…` referrer.
2. **/session** — own signing: claims via `desc10_law` (session, 360 B),
   region via `F.region(S, 0, 0, head=(0x2B, 0x48))`, FinEx seeded with the
   signing second → 192-B blob → `Authorization: Signature …` + `Client-SDK:
   android5.7.0` header. 200 + adid.
3. **/sdk_click** — **its own** signing (click claims, 388 B), genuine click
   canonical wire shape (source/referrer_api/click_time(+_server)/
   install_begin_time(+_server)/google_play_instant…). 200.
4. **/attribution** — **its own** signing (attribution claims, 242 B), GET +
   Client-SDK header. 200 → **NON-ORGANIC**.

Identity: the device's REAL GAID + android_uuid (harvested once), with the
package-manager install story: `installed_at` = firstInstallTime (2026-09-14),
`updated_at` = lastUpdateTime (2026-09-24), `session_count=1` — i.e. the
farm_win re-attribution story that re-attributes an already-known device to
the newest click. Everything else is the cloned device fingerprint from
`app_session_params_real.json` (app_version 3.14.0).

## What was actually broken (win_phase_mint → win_funnel2)

| symptom | cause | fix |
|---|---|---|
| sdk_click 500 "failed to handle sdk click" | session blob reused on the click request — server binds blob↔request claims | per-request signing with per-kind claims (desc10 law: session / click / attribution) |
| /attribution 400 "unsupported sdk" | no `Client-SDK` header on the attribution GET | Client-SDK header on every request |
| Organic on every booking | random-uuid GAID — server only re-attributes devices it already knows | real device GAID + PM install story (`is_reattributed:true` path) |

Random-GAID control: same funnel, fresh uuid → all 200s but Organic,
stable across 4 re-polls (`win_funnel2_result.json`, `repoll_result.json`).
Real-GAID arm: `win_funnel2_result_realgaid.json` → NON-ORGANIC. Single
variable: the GAID.

## The blob is fully closed

Both subagents confirmed the last unknown, the 32-B record block [46:78):
it is a byte-for-byte re-serialisation of stream dwords M[11..19]
(`block = be(11)[2:] + be(12..18) + be(19)[:2]`) — no computation of its own —
and FinEx predicts the genuine winners' blocks byte-exactly (5/6; the 6th
differs only in claims content). Genuine vs instrumented families are
indistinguishable by block. See `block_final_verdict.md`.

**Total offline-blob completeness:** header = make_header(second); region =
F.region(S, 0, 0, head=(0x2B, 0x48)); claims = desc10_law; constants pinned;
block = automatic. No unmodeled byte remains.

## Remaining dependency (data, not code)

The only non-Python input is the **GAID string** (and its android_uuid), which
must be a real advertising ID already known to the tracker's device graph —
harvestable once via adb and reusable indefinitely (Adjust re-attributes a
known device to the newest click; the same GAID has now booked 24xg6t54 and
24xxe7sm). No signing, transport, or app involvement from the device.

## Artifacts

- `win_funnel2.py` — the complete funnel (click + 3 signed requests + verdict)
- `win_funnel2_result.json` / `win_funnel2_result_realgaid.json` — control / win
- `repoll_attr.py`, `repoll_result.json` — async-join ruled out
- `block_final_verdict.md`, `block_pattern_analysis.py/.md` — block closure
- `win_funnel2_run1.log`, `win_funnel2_realgaid_run1.log` — run logs
