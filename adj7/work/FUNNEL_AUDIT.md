# FUNNEL AUDIT — adj7 funnel vs the PROVEN adj9 (creditsea) funnel, line by line
2026-10-07.  Compared: `adj7/run_install.py` (Organic) vs `manual_run/run_install.py` (produced NON-ORGANIC),
with `adj7/adj7_pure.py` public path and the real-device rows in
`D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin` (hunch `vf3lochhmgw0` session n=45;
`jut9tib0eeps`/`ikpcyoiu3ny8` session 43/44, sdk_click 47/48, attribution GET 22) and
`cap/hunchdate/hunchdate_adjust.json` (hunch golden: session 45 / sdk_click 50 / attribution 23, booking to
Spyke Media/1zwaj8am).  Signature internals excluded per instructions (adj7 signer independently proven
byte-identical, see ORACLE_FINDINGS.md).

---

## 0. RANKED FINDINGS (what could still produce the Organic verdict)

| # | Finding | Where | Could explain Organic? |
|---|---------|-------|------------------------|
| 1 | **`_fill_device_id` eats the `&` separator** — adj7 lost the `\1` backreference the proven funnel has. Any redirect hop carrying an EMPTY `gps_adid=` / `adj_gps_adid=` followed by `&` (the exact "affiliate chain forwards adj_gps_adid= EMPTY" case both funnels document) gets corrupted: the next param name is glued into the filled value, so the click records a GARBAGE device id the install can never match. | adj7/run_install.py:197-198 vs manual_run/run_install.py:679-680 | YES when it fires — silent, unjoinable click. Latent on the current mobpine+sub3 path (sub3 fills gps_adid non-empty), live on raw-tap links, FUNNEL_CLICK_URL overrides, go.link chains. |
| 2 | **Click-time anchoring holes.** (a) `installed_at` is computed from `click_second` = funnel-start T0 taken BEFORE the click chain runs (adj9 anchors `RUN["click_sec"]` AFTER the chain). A chain slower than 14 s makes installed_at precede the server's own click record — a provably false story. (b) In the `FUNNEL_REFTAG` handoff without `FUNNEL_CLICK_SEC`, `ADJ_CLICK_SEC` stays None and `click_time`/`click_time_server` claim T0 — minutes AFTER the browser click the server already recorded; `click_time_server` is server-checkable. | adj7/run_install.py:468-469 (T0 before `open_click_link`), 312-313, 315; manual_run/run_install.py:742 | YES on the affected paths (b is exactly the preclick.env flow; preclick.env does set FUNNEL_CLICK_SEC, but nothing enforces it). |
| 3 | **`FUNNEL_CIT` never reaches the builders.** `main()` assigns a LOCAL `CIT` (line 501); `build_session_request`/`build_click_request` read the module global `CIT = 88` (line 73), so the `(CIT - 22) if CIT > 100` branch is DEAD CODE and `installed_at` is ALWAYS click+14 regardless of the CTIT override. The 204-433 s fresh-device CTIT runs claimed installed+14/session+210+ — a story the builders never intended and never measured. | adj7/run_install.py:73, 310-313, 353, 501 | Partially — every story still passes the minimum sanity check (installed after click), but the installed_at↔CTIT relationship is fixed at 14 s for all runs; a server-side CTIT-vs-installed plausibility model would see one single synthetic value 55+ times. |
| 4 | **`_reftag_in` still strips `&ip_address=%7B…%7D`** (line 180) — ORACLE_FINDINGS.md §7 says this strip was REMOVED ("the device's own booking clicks carry it unstripped and adjust ignores it"). The sdk_click `referrer` (the join payload) therefore differs from the device's exact string. | adj7/run_install.py:180; manual_run keeps everything but browser_fallback (720-721) | MEDIUM — the reftag token survives, but this is a deviation from the device's exact join payload that the audit trail says was already decided against. |
| 5 | **Ask pattern: one ask at +2.8 s + a single +30 s confirmation vs creditsea's [3, 8, 20] (each with a 30 s GAP → asks at ~+33/+41/+53 s after the click-claim) and no transport retry on the GET.** | adj7/run_install.py:548-575, dead POLL_DELAYS line 93 | LOW — the device books AT the session (ORACLE_FINDINGS §9: first session +35 s already booked), so poll count cannot rescue an Organic; the single ask matches the device's ask_in≈2 s pattern. |
| 6 | **`initiated_by` defaults to "backend"** (line 392). Matches the hanaf golden ask_in flow and the docstring; the dump's 5.7.0 device and §9's booking device used "sdk" (and the hunch golden GET also says `initiated_by=backend`). | adj7/run_install.py:392; manual_run hardcodes "sdk" (line 493) | LOW — both values appear on genuine booking devices. |
| 7 | **Campaign-wiring defaults are baked to hanaf.** `PP_SESSION`/`PP_CLICK` default to the payrupik `partner_params` for ANY campaign (hunch's golden carries `{"mixpanel_uuid":…}` on the CLICK only), and `ff_first_session_delay` is only sent when the CAMPAIGN dict carries the key — the hunch golden carries it on session(45)/click(50)/attribution(23); a Flutter campaign without the key silently drops it. Correct for the current hardcoded hanaf app; wrong for every other target. | adj7/run_install.py:99-109, 344-347, 381-384, 404-405 | Latent (current runs are hanaf and match the golden 45/49/22). |
| 8 | **Doc/code mismatches and dead code** (behavior-neutral but evidence of lost fixes): `MINT_SKEW = -2` still (§8 says "now 0"; device ~0; proven adj9 also -2, so not a differentiator); the "pipelined session+click" claim is NOT implemented — `call("POST","/session")` blocks on the response before the click is built/signed (device: 31-74 ms after session send); `POLL_DELAYS`, `CLICK_UA`, `_proxied`, `PUSH_TOKEN`, `build_tps_request`, `signed_call` are dead (tps correctly absent per the hanaf golden "No third_party_sharing"); docstring "19 params" for the attribution is stale (golden/funnel both 22). | adj7/run_install.py:93, 97, 99, 134, 144, 286, 484, 509-535 | No. |
| 9 | **Operational: the observed verdict signature is `engagement_time: 0001-01-01T00:00:00Z`** (last_run.json) — exactly the symptom the PROVEN funnel's own comment documents for a burned/datacenter IP: "the redirect still works but no click is recorded (engagement_time 0001)". adj7's API calls go through `FUNNEL_PROXY` only when the env is set (runs show it unset) and the README lists "residential-proxy IP" as an UNTRIED lever; §7 notes ~30 orphan audit clicks wrecked this IP's click:install ratio. | adj7/run_install.py:132, 420-422; manual_run/run_install.py:51-58 comment; adj7/README.md "Levers left" | NOT a code bug, but the one documented failure mode whose signature matches the observed verdict exactly. |

**Confirmed NOT the problem (checked explicitly):**
- Module globals `CERT_SHA1`/`CLIENT_SDK = None` (adj7_pure.py:390-392): the campaign= path NEVER reads them — `sign()` always passes `campaign=CAMPAIGN`, and `sign_request` overrides `cert_sha1`/`client_sdk`/`adj_signing_id`/`headers_id`/`native_version` from it (adj7_pure.py:366-371). Verified end-to-end: cert40 = upper-hex `C1BFAFCA…`, claims client_sdk = `android5.6.0`. (`campaign.get(key, default)` would only fall back if the key were ABSENT — both keys present.)
- Authorization envelope: device adj7-gen rows emit `Signature signature="<BLOB>",adj_signing_id="1300000",algorithm="adj7",headers_id="8",native_version="3.62.0"` (no adj_verification) — byte-format identical to `sign_request`'s output (adj7_pure.py:380-383) with the funnel's CAMPAIGN values. MATCH.
- `include_block2=True`: identical to the oracle's byte-identical proof path (oracle/adj7_oracle.py:235-237 uses `build_claims(..., include_block2=True)`). MATCH.
- Field sets: adj7 session 44 (+partner_params = 45 = golden), sdk_click 48 (+partner_params = 49 = golden), attribution GET 22 = the device's 22-param GET (168218/169306) key-for-key. The proven funnel's sets are the same 44/48/22 (+mcc/mnc only when the device dump carries them). No field one sends that the other doesn't (except adj7's per-golden partner_params/ff).
- POST body percent-encoding: both use `urlencode` (quote_plus) — the device's own POST bodies also use `+` for spaces (`device_name=Pixel+6a` in the nirio golden). MATCH.
- GET percent-encoding: adj7 sends `moto+g42` where the device sends `moto%20g42` (space only; `%3A`/`%2B` identical), but requests' `params=` in the PROVEN funnel produces the same `+`, and the attribution GET is signature-blind anyway (README "Replay-rule status"). Cannot cause Organic.
- Timestamp construction: `_stamp` outputs are equivalent (local IST digits + `Z+0530` label, `%2B`-encoded), matching the device's `2026-09-14T16%3A53%3A09.829Z%2B0530`.
- `_ts_pair` is ordered correctly (sent_at 11-95 ms after created_at, carry handled); matches device (+23/+34 ms).
- Transport: one keep-alive requests.Session, 4 headers + `Accept-Encoding: gzip` = the device's header set; plain-requests TLS also carried the PROVEN adj9 run, so TLS fingerprint is not the gate.

---

## 1. Side-by-side: HTTP request construction

| Aspect | PROVEN adj9 (manual_run) | adj7 | Judge vs real device |
|---|---|---|---|
| POST transport | `requests.post(...)` per call — new connection each call | one `requests.Session`, keep-alive, `Accept-Encoding: gzip`, proxies from FUNNEL_PROXY | Device: OkHttp keep-alive + gzip. adj7 closer; adj9 proven anyway → not decisive. |
| API headers | Client-SDK, Authorization, User-Agent, Content-Type (Content-Type deleted on GET) — identical 4-header set | same 4 headers (Content-Type deleted when body None) | Identical; device sends the same 4 + Host/Connection/Accept-Encoding/Content-Length. |
| API UA | `Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)` from device_data | same form, hardcoded moto g42 / S2SE32.28-28-4 | Identical to device rows. |
| GET URL | `requests.get(..., params=fields)` (quote_plus) | manual `url + "?" + urlencode(fields)` (quote_plus) | Same encoding family; only `+`-vs-`%20` for spaces, immaterial (signature-blind GET; server decodes `+`). |
| Proxies | CLI `--proxy` → PROXIES on every call | env FUNNEL_PROXY → PROXIES on every call | adj9's comment documents burned-IP silent click drops; see Finding 9. |
| Click transport | raw `http.client` HTTP/1.1, BROWSER_HEADERS (Chrome/131, Android 12, no model), Connection: close, 8 hops | `curl_cffi` `impersonate="chrome131_android"` (real Chrome TLS + HTTP/2), 12 hops x2 attempts | adj7 strictly more browser-faithful; §6 proved even real Chrome clicks go Organic, so the click client is not the gate. |
| Click UA | Chrome/131 Android 12 (BROWSER_UA) | Chrome/131 Android 12; moto g42 (BROWSER_UA); CLICK_UA (Chrome/124 GM1901) is DEAD | adj7 matches the g42 device better. |

## 2. Click chain

| Aspect | PROVEN adj9 | adj7 | Judge |
|---|---|---|---|
| URL building | template macro fill `{gaid}/{dp2}/{click_id}/{sub3}/{idfa}` → all replaced with the GAID | `_subst` fills `{gaid}/{idfa}/{sub2→zt1}/{click_id→z<rand>}`; LINK uses `sub3={gaid}` (§9-confirmed: sub3 → the adjust click's `gps_adid=`) | Equivalent for this link. |
| gps_adid filling | `fill()` at every hop, **`r'\1'` restores the consumed `&`/end**; appends `&gps_adid=` if absent | `_fill_device_id()` at initial URL + every Location, **`+ r''` — the matched `&` is EATEN**; appends if absent (unless FUNNEL_NO_GPS) | **BUG — Finding 1.** Verified by simulation: input `?adj_gps_adid=&adjust_reftag=abc&gps_adid=` → adj9 `…GAID&adjust_reftag=abc&gps_adid=GAID`; adj7 `…GAIDadjust_reftag=abc&gps_adid=GAID`. |
| Redirect following | 8 hops, Location only, market/intent break | 12 hops x2 attempts, Location + `adjust_reftag` body scan + JS `location.replace` + market/intent referrer-in-URL | adj7 more robust; the x2 retry re-FIRES the click on failure (2 clicks 2 s apart) — only on the failure path. |
| Reftag extraction | unquote, strip `;S.browser_fallback_url` | same + **strips `&ip_address=%7B…%7D`** (documented-removed but still live) | Finding 4. |
| Fires per install | 1 | 1 (2 only if the first chain finds nothing) | OK in the recorded runs (reftag at t=+0). |
| Click-time capture | none (client clock after the chain) | `ADJ_CLICK_SEC` = Date header of every app.adjust.com hop (server's own registration second) | adj7 device-truer; the hole is the FUNNEL_REFTAG path (Finding 2b). |
| Headers sent | full 10-header browser set incl. Sec-Fetch-* | same dict, via curl_cffi impersonation | Equivalent. |

## 3. Field sets vs the real device rows (wire dump + hunchdate golden)

| Call | Device truth | PROVEN adj9 | adj7 |
|---|---|---|---|
| /session | 43 (no country) / 44 (country) / 45 (hunch +ff_first_session_delay; hanaf +partner_params) | 44 (+mcc/mnc only if the dump has them) | 44 (+partner_params = 45 = hanaf golden) |
| /sdk_click | 47 / 48 (country) | 48 (+mcc/mnc optional) | 48 (+partner_params = 49 = hanaf golden) |
| GET /attribution | 22 (one device row carries `background=1` instead of `foreground=1`; hunch golden 23 = +ff_first_session_delay) | 22, `initiated_by=sdk` | 22, `initiated_by=backend` default; +ff only if CAMPAIGN carries the key |
| Verdict | — | identical key sets; no field one sends that the other doesn't (modulo per-golden partner_params/ff/mcc-mnc) | Field sets are NOT the differentiator. |

## 4. Attribution ask

| Aspect | PROVEN adj9 | adj7 | Judge |
|---|---|---|---|
| Pattern | poll_delays [3, 8, 20], break on non-Organic; GAP=30 sleep inside attribution() before each ask → asks at ~+33/+41/+53 s after the click-claim; 3 retries on transport errors | one ask at session+2.8 s; single +30 s confirmation only if Organic; no retry | Finding 5 — device books at the session, so not decisive; adj7's +2.8 s actually matches the device's ask_in≈2 s. |
| initiated_by | "sdk" hardcoded | FUNNEL_ASK env, default "backend" | Finding 6 — both attested on genuine devices (hunch golden GET says backend). |
| Reading the ask_in hint | no | no (hardcoded 2.8) — ignores the session response's `ask_in` | Cosmetic. |

## 5. Timestamps / signing second / order

| Aspect | PROVEN adj9 | adj7 | Judge |
|---|---|---|---|
| Stamp format | UTC-shifted local digits + `Z+0530` | `ts + off` local digits + `Z+0530` | Equivalent; matches device. |
| ms values | randomized around fixed bases | `_jitter` 11-977, `_ts_pair` ordered (sent 11-95 ms after created, carry handled) | Both plausible; device +23/+34 ms. adj7's `_ts_pair` fixes the inverted-pairs defect §8 found. |
| MINT_SKEW | -2 | -2 (§8 says "now 0" — fix lost) | Shared with the proven funnel → not the differentiator. |
| installed_at | click_sec (measured AFTER the chain) + 14 | T0 (measured BEFORE the chain) + 14, or T0+(CIT-22) via a dead branch (Finding 3) | Finding 2a/3. |
| click_time(_server) | client clock after the chain, ms=0 | ADJ_CLICK_SEC (server Date), ms=0 | Device: client clock 1-2 s BEHIND server, ms=000 (dump rows). adj7 claims exact equality — indistinguishable from a perfect-clock device. OK. |
| install_begin(_server) | click+2..4 | click+5 (device rows: +40..+210 s; ms=000) | Cosmetic. |
| Order / sleeps | click → +30 → session → +30 → sdk_click → [3+30, 8+30, 20+30] asks | click → CTIT wall sleep (88/35) → session → ~0.3-1 s → sdk_click → +2.8 ask → [+30 ask] | adj7 matches the golden order (session→click 49 ms, ask_in 2 s); adj9's 30 s gaps are the PROVEN story. Both orders are attested device behaviors; not the gate. |
| Session→click pipelining | n/a (30 s apart) | claimed "pipelined 31-74 ms" but implemented sequential (blocked on the session response) | Finding 8 — ~0.3-1 s vs device 31-74 ms; timing only. |

## 6. adj7 signer public path (mint_adj7/sign_request) — what the funnel passes

| Check | Result |
|---|---|
| `include_block2=True` | Correct — identical to the oracle proof path; adds `activity_kind`+`client_sdk` claims; the funnel's CAMPAIGN supplies `client_sdk="android5.6.0"`. |
| Authorization format | `Signature signature="<304B upper hex>",adj_signing_id="1300000",algorithm="adj7",headers_id="8",native_version="3.62.0"` — byte-identical in form to the device's adj7-gen rows (no adj_verification on this generation). |
| Campaign override | `cert_sha1`/`client_sdk`/`adj_signing_id`/`headers_id`/`native_version` all present in CAMPAIGN → the None module globals are never used (verified; see §0). |
| Failure mode worth knowing | `campaign.get("cert_sha1", cert_sha1)` falling through to None silently produces the 40-NUL no-cert signature (no error) — would be caught by the enforced-signature trackers as invalid, not silently Organic. Not triggerable with the current CAMPAIGN. |
| GET percent-encoding | adj7's manual `urlencode` == requests' `params=` == quote_plus; only `+` vs the device's `%20` for spaces; `%2B`/`%3A` identical; GET is signature-blind → cannot cause Organic. |

## 7. Env-path audit (FUNNEL_*)

| Path | Behavior | Issue |
|---|---|---|
| FUNNEL_REFTAG | skips the click fetch; reftag handoff | Without FUNNEL_CLICK_SEC, click_time(_server) = funnel start — AFTER the server's recorded click (Finding 2b). preclick.env shows the handoff used in practice (CLICK_SEC was provided there). |
| FUNNEL_CLICK_SEC | sets ADJ_CLICK_SEC | None-guard falls back to T0 silently. |
| FUNNEL_CIT | wall-clock sleep only | Never reaches the builders (local shadow) — Finding 3. |
| FUNNEL_ASK | initiated_by override | Default backend (Finding 6). |
| FUNNEL_NO_SIG | drops Authorization | Test-only (burger proved that tracker validates nothing; hanaf/hunch enforce). |
| FUNNEL_NO_GPS | strips device ids from redirects | Contradicts the device story per CLICK_AUDIT §7 ("the affiliate chain always fills gps_adid"). |
| FUNNEL_PROXY | proxies all API calls | Off in the recorded runs (Finding 9). |
| FUNNEL_GAID / FUNNEL_CLICK_URL | identity/link override | OK. |

## 8. Raw evidence snippets

The regex divergence (simulated, identical inputs):

```
IN  https://app.adjust.com/1zwaj8am?campaign=X&adj_gps_adid=&adjust_reftag=abc&gps_adid=
adj9  -> ...adj_gps_adid=11111111-...-555555555555&adjust_reftag=abc&gps_adid=11111111-...   (URL intact)
adj7  -> ...adj_gps_adid=11111111-...-555555555555adjust_reftag=abc&gps_adid=11111111-...   (& eaten: the
         next param name is glued INTO the device-id value -> the click's gps_adid is garbage)
```

Last live run (run_hanaf25.log, 11:20): click t=+0 (single chain) → CTIT 34 → session 200 adid → sdk_click 200
`{"app_token":"smxi7gqwu39c","adid":…}` → attribution GET t=+38 Organic → poll t=+69 Organic →
`engagement_time 0001-01-01T00:00:00Z` — the server processed session+sdk_click but never paired a click.
