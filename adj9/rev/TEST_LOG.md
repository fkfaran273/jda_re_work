# adj9 attribution campaign — full test log (2026-09-14)

Objective: reproduce a NON-ORGANIC Adjust attribution for `com.penti.app`
(app_token `jut9tib0eeps`, tracker `https://app.adjust.com/1sd1lk6a`)
with offline-crafted adj9 signatures. Status: **all offline attempts Organic**.

## 0. Baseline (proven, unchanged all day)

- Header = Random3(second), 4xBE u32 — 94/94 + 4/4 SAZ law-match (`header_gen.py`).
- Body = FinEx VM over 11 descriptors, 48/48 byte-exact on captured input
  (`fin_vm2.py`, `fin_descs.json`); control re-verified exact today.
- `adj_verification = KlcAG2cbAAsKSl1KVi0FGiJbDHMI`, signing id `1500000`,
  `algorithm=adj9`, `headers_id=10`, `native_version=5.0.0`, Client-SDK `android5.7.0`.
- `libsigner.so` byte-identical old vs new APK (md5 `dbe36c64…`), Adjust SDK
  still `android5.7.0`; app updated 3.12.1 → 3.13.9 (code 31309).
- Every crafted call returns HTTP 200 (garbage → 400, so the gate is real).
- Devices: rooted moto g42 `ZD2228MY3X` (whcap source, AAID `f476b3d4…`,
  Adjust uuid `1bdf6b7c…`); non-root CPH2585 (AAID `b60338da…`, got real
  non-organic, screenshot-proven); POCO 23122PCD1G (AAID `0d0b7778…`).

## 1. Signature/body bugs found AND fixed (live-verified in)

| # | bug | fix | effect |
|---|---|---|---|
| 1 | HW swap 14ch vs 15ch silently no-opped (`swap_eq` length gate) | equal-length-only + miss logging | exposed bug 2 |
| 2 | `com.android.vending12` swap ate updated_at's leading `2` → body stamp year `16026` on EVERY run ever | swap removed; both install stamps swapped fresh | clean bodies, still Organic |
| 3 | invented `click_id` in sdk_click (real app never sends it) | removed | still Organic |
| 4 | missing `sdk_info` call (SAZ has 4 calls) | added → later REMOVED (winning 3.13.9 install never sends it) | still Organic |
| 5 | `referrer_click_timestamp_seconds` tip — dex forensics: Adjust READS Play values but `PackageBuilder#getClickParameters` emits only the 8 known keys; strings belong to Firebase-strip + Clarity/TikTok reads | not added (would deviate from real app) | n/a |
| 6 | market:// redirect breaks urllib (headers lost) | http.client tracker fetch | harvest reliable |
| 7 | Fiddler/system proxy breaks urllib TLS | ProxyHandler({}) direct bypass | 200s restored |
| 8 | unexpanded `{click_id}`/`{sub3}` macros poisoning clicks | expansion before fetch | clean clicks |

## 2. Offline chain matrix (all: fresh reftag, all endpoints 200)

| run | profile | variations vs baseline | adid | verdict |
|---|---|---|---|---|
| tracker_chain2 early | DN2101/3.12.1 | click→session→attr, tracker click w/ click_id+idfa+callbacks | 1261d1bf… | Organic |
| +click_id/sdk_info | DN2101 | +sdk_info, +click_id in click | 42fa1f48… | Organic |
| CPH2585 fix | CPH2585/3.13.9/api36 | real CPH props, click_id dropped | 551da121… | Organic |
| +4min delay re-poll | same record | async-join hypothesis | same | Organic (stable) |
| plain-URL click | CPH2585 | no click_id/idfa/callbacks on click | cebb5376… | Organic (+5h re-poll: Organic) |
| body-fix verify | CPH2585 | corruption fix confirmed (no SKIP) | 33c46bf4… | Organic |
| random push_token | CPH2585 | fresh FCM-shaped token (was SAZ replay) | 3b69badd… | Organic |
| production link | CPH2585 | expanded macros + EC2 callbacks | cebb…/33c4… | Organic |
| faithful body | CPH2585 | true-length claims, #7=len, 359 B, exit-clean | 445f580c… | Organic |
| POCO live-data | POCO/3.13.9/api35/tr/+0200 | REAL adid `0d0b7778` + REAL pasted referrer `csD2mExrEMpLs` | ee45f94d… | Organic |
| stamped phone click | moto | tracker click fired on phone w/ same gps, chain offline | 6924e21a… | Organic |
| phone-egress submit | moto | minted local, ALL calls via phone curl (IP 106.219.162.119) | 25cbf645… | Organic |
| winner-mirror | moto | tr/2237/high, no mcc/mnc, −2s server skew, exact 22-param attr, no sdk_info | 89e69ca0…/2c6c9566… | Organic |

Also from parallel sessions (slices 86/87): real #0+H (attempt7), Chrome TLS click,
Dalvik-exact headers, CTIT 6s→5min, session orders — all Organic.

| samsung live-data | SM-M526B/3.13.9/api33/tr/+0200 | REAL adid `9c39b6ca` + REAL reftag `cAHE9yNSfVX9D` + REAL click epoch 1789390573 + winner mirror | c659e971… | Organic |
| phone-egress submit | moto, all 4 calls via phone curl (IP 106.219.162.119) | mint local, submit on-device | 25cbf645… | Organic |
| junk-param purge | moto | dropped `no_sim` (leaked helper key!) + `install_version` from session; exact 22-param attr | 0c31d1d3… (Samsung-UA reftag cZMDI2UJu6M2T) | Organic |

Egress finding: PC **and** phone share public IP `106.219.162.119` (same LAN).
IP was never a variable — click/install same-IP in every run, winning or not.
Field audit of base #10 (360 B, single concat run): every run maps to a winner
wire value or a swap (`1500000`, `android5.7.0`, headers `10`, `session`,
store, `service`/`phone`/`production` all static-correct). Zero stale constants.

## 3. On-device experiments (moto g42, Play-installed)

| # | setup | installReferrer (device-stored) | attribution |
|---|---|---|---|
| M1 | hooked (oracle scoped in), old AAID | `utm_source=google-play&utm_medium=organic` | Organic (wy7261z) — invalid test, no tracker referrer ever arrived |
| M2 | oracle scope REMOVED (DB surgery + reboot, maps-verified clean), fresh AAID `b0611920` | `(not set)` | **NON-ORGANIC** `24pxw9rl` VKM, engagement 07:34:43Z |
| M3 | oracle scope RESTORED (hooked again, verified in LSPosed log), fresh AAID `9abd2f3e` | `(not set)` | **NON-ORGANIC** `24ibsv01` VKM, engagement 10:43:55Z |
| M4 | hooked, fresh AAID `d016e7e4`, full-funnel Fiddler capture | `(not set)` on wire (Fiddler-confirmed) | **NON-ORGANIC** `24pxw9rl` VKM, engagement 10:25:58Z |

Conclusions: hooks/root do NOT gate attribution (M2 vs M3). Server keys records
by AAID, first verdict sticky (re-query returns original record months-stable).
Stored/wire referrer is `(not set)` in ALL THREE wins — the join key is NOT the
referrer string. Engagement predates install by 40min–3h in every win.

## 4. Winner wire shape (M4 Fiddler capture, `penti_android_test.saz`)

- session (43 params), sdk_click (47), attribution GET (22, `initiated_by` first,
  NO push_token), NO sdk_info call.
- `click_time_server` = click_time − 2s; `install_begin_time_server` =
  install_begin_time − 2s (Play clock skew, not our +1s fabrication).
- `language=tr` on en-IN device (app forces Turkish); display `1080x2237`,
  density `high`; NO mcc/mnc (no SIM); no `click_id` anywhere.
- All three mirrored offline in "winner-mirror" run → still Organic.

## 5. Open unknowns (nothing byte-level left untested)

1. The server-side join key (engagement links without referrer; AAID-link,
   IP-link, fingerprint-link, Play-timestamp corroboration ALL tested dead).
2. Play install provenance (`install_begin_time` backed by a genuine Play
   install) — unforgeable off-device by definition.
3. TEE-HMAC realism — server cannot recompute it (key never leaves TEE),
   never transmitted, never testable; attempt7 (real H) already Organic.
4. Whether the 07:34/10:25/10:43Z engagements are real campaign clicks,
   our own datacenter clicks, or phone-side clicks (Chrome keeps no history
   for 302 hops; unresolved).

## 6. Scripts (all in `rev/`)

- `adj9_full_chain.py` — the one script: `make_signature()` + 4 API methods,
  profiles `cph`/`moto`/`poco`, macro expansion, proxy bypass. Current.
- `phone_submit.py` — mint local, submit via phone curl (phone-IP egress).
- `attr_check.py` — signed attribution lookup by gps (+optional exact auid).
- `tracker_chain2.py`, `nonorganic_test2.py`, `tracker_chain.py` — superseded.
- `saz_session_log.py` — .saz extractor (header-law check + params dump).
