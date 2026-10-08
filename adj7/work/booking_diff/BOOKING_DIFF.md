# BOOKING DIFF — golden BOOKED NON-ORGANIC (payrupik_new_.saz) vs our ORGANIC funnel (run_hanaf6/7)

Reproducible with `python booking_diff.py` (this directory). It extracts the
golden requests **byte-exact** from the SAZ, rebuilds our wire requests from
`run_install.py`'s own builders + `call()` (using `last_run.json` =
run_hanaf7's identities), and diffs headers / bodies / queries at the RAW
BYTES level. Machine output: `booking_diff_out.json`. Byte-exact golden
copies: `golden_raw/{42,43,44,45}_{c,s}.txt`. Our rebuilt wire:
`our_wire/{session,sdk_click,attribution}.txt`.

Golden: sid 42 POST /session, sid 43 POST /sdk_click, sid 44 GET
/attribution, sid 45 POST /event — all HTTP 200, sid 44 answered **NON-ORGANIC
248wk8ym / VL-Alliance::HM2::HM2_1722_** (adid 6b575c41bbefc8caaccaf6faa01eac3a,
GAID 0a5863d0-66f6-4d15-b9ab-d388b77c8ba3).
**The CLICK is not in the SAZ** — verified: all 64 sessions are the phone's
in-app traffic (CONNECT tunnels + payrupikloan.in / adjust / facebook /
firebase); the Play-Store click predates the capture. Unavailable by design.

---

## 0. What is ALREADY IDENTICAL (verified, do not touch)

| item | evidence |
|---|---|
| Header set AND order, all 3 signed requests | POST: `Client-SDK, Authorization, Content-Type, User-Agent, Host, Connection, Accept-Encoding, Content-Length`(last). GET: same minus Content-Type/Content-Length. Golden == ours, exact wire order. |
| `Content-Type` | `application/x-www-form-urlencoded` — **no charset**, both sides |
| `Client-SDK` | `android5.6.0` both |
| `Connection` | `Keep-Alive` both |
| `Accept-Encoding` | `gzip` both |
| `Authorization` structure | `Signature signature="<blob>",adj_signing_id="1300000",algorithm="adj7",headers_id="8",native_version="3.62.0"` — same param keys, same values, same blob length (608 hex / 304 B); zero auth diffs on all 3 requests (signatures proven byte-exact in cap/REPLAY_RULE_RESULT.md probe G) |
| Timestamp format | every created_at/sent_at/click_time*/install_*/installed_at/updated_at: `YYYY-MM-DDTHH:MM:SS.mmmZ+0530` — **local digits + offset on both sides**, format-identical |
| Percent-encoding | **zero encoding-only diffs on any common field**. Space law proven (also synthetically, since our device_name has no space): POST bodies use `quote_plus` (space→`+`; golden `device_name=moto+g42` in sid 42/43), GET query uses `quote` (space→`%20`; golden `device_name=moto%20g42` in sid 44) — our two encoders reproduce both forms exactly. `:`→`%3A`, `+`→`%2B`, `{"…"}`→`%7B%22…%22%7D` all identical |
| GET /attribution | **22 params, same names, SAME ORDER** (`initiated_by` first, `tracking_enabled` last) |
| referrer param trail | `adjust_reftag=<13ch>&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_` — identical shape, no sub2/zt1 suffix on either side |
| Content-Length integrity | golden hdr == body bytes on all POSTs (1124/1420/1114) |
| `ask_in` | golden session response `{"app_token","adid","ask_in":2000}`; our session responses carry `ask_in:2000` too (run_hanaf.log L41, run_live2.log L41) — no response-side difference except the verdict itself |
| Flow order | click → session → sdk_click(+~50 ms) → attribution(+2.8 s, ask_in) — same order |

---

## 1. THE DIFFS, ranked by booking impact

### RANK 1 — sdk_click is MISSING `click_time_server` and `install_begin_time_server`  (class a: golden sends, we omit)

The only missing-field pair in the whole flow, and it sits in the ONE request
that carries the click story (source=install_referrer). Both genuine captures
carry them (moto g42 here; Pixel 6a in work/FLOW_DIFF.md):

```
golden sid 43:  click_time=2026-10-06T15:40:25.000Z+0530
                click_time_server=2026-10-06T15:40:25.000Z+0530   <- ours: ABSENT
                install_begin_time=2026-10-06T15:40:26.000Z+0530
                install_begin_time_server=2026-10-06T15:40:26.000Z+0530
                                                              <- ours: ABSENT
ours  sid 43:   click_time=…T17:46:03.000Z+0530  (click_time_server missing)
                install_begin_time=…T17:46:05.000Z+0530 (server twin missing)
```

These are the Play InstallReferrer API's **server-side echoes** — the real
client got them from the genuine Play read; a forged referrer cannot. They
are the classic validation signal for `source=install_referrer` clicks
(our sdk_click is accepted 200 but produces NO engagement → Organic,
engagement_time `0001-01-01T00:00:00Z`). In the golden both pairs are
identical to their client twins, `.000` precision. FLOW_DIFF.md's old
decision ("omit — no real Play read") is the prime suspect.

**Fix:** add `click_time_server = click_time` and
`install_begin_time_server = install_begin_time` to
`build_click_request()`. They enter the signed map (law: signed map == wire
params + block2) — our mint signs whatever we send, no signature risk.

### RANK 2 — the device/geo story is a DIFFERENT phone than the golden (class c: value consistency)

The task premise "the same device profile" is **contradicted by the runs**:
run_hanaf6/7 logs say `device OnePlus GM1901 (Android 10, api 29)` — the
funnel still runs the old payrupi-era profile, while this golden is the
moto g42. Every device field differs:

| field | golden (moto g42) | ours (run_hanaf6/7) |
|---|---|---|
| country | **IN** | **AE** |
| api_level / os_version | 31 / 12 | 29 / 10 |
| device_name | moto g42 | GM1901 |
| device_manufacturer | motorola | OnePlus |
| hardware_name == os_build | S2SE32.28-28-4 | GM1901_14_201019 / QKQ1.190716.003 |
| display_height | 2237 | 2218 |
| app User-Agent | `Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)` | `Dalvik/2.1.0 (Linux; U; Android 10; GM1901 Build/QKQ1.190716.003)` |
| click User-Agent (BROWSER_UA) | real Chrome on the moto g42 (Android 12) | `Mozilla/5.0 (Linux; Android 12) …` — claims Android 12, **no model** |

Two inconsistencies the golden does not have: (1) our click claims
**Android 12** while the app 2 s later claims **Android 10 / GM1901** —
one device, two stories; (2) the app claims **country=AE** from the same
Indian IP that the click, session and golden all share (golden: IN == IP
geo). Caveat stated honestly: the reftag is the join key, so a profile
mismatch alone is not proven to flip the verdict (the older genuine Pixel 6a
capture claimed AE per FLOW_DIFF §13 and still booked) — but the
click-vs-app device consistency is a story property the golden has and we
do not, and it is free to fix.

**Fix:** in `run_install.py` set DEVICE to the golden profile (api_level 31,
os_version 12, device_name "moto g42", device_manufacturer "motorola",
hardware_name/os_build "S2SE32.28-28-4", display_height 2237, country "IN",
timezone "+0530" already) and make BROWSER_UA name the same device:
`Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/131.0.0.0 Mobile Safari/537.36`.

### RANK 3 — sdk_click sends an EXTRA field `initiating_package_name` (class b: we send, golden omits)

Golden sends `initiating_package_name=com.android.vending` on **/session
only** (position 40, between package_name and os_name) — never on
/sdk_click, never on /event. Ours injects it into the sdk_click (position 17).

**Fix:** delete it from `build_click_request()`.

### RANK 4 — session sends an EXTRA field `push_token` (class b)

Golden moto g42 session has **no** push_token (45 fields; same for its
sdk_click — ours also correctly omits it there). Our session fabricates an
FCM token (position 31). Note: the adj7 signed map **excludes** push_token
(law-verified in REPLAY_RULE_RESULT.md), so it cannot break the signature;
and the older Pixel 6a genuine capture DID carry one — it is device-state
dependent. Low booking risk either way; remove it to match this golden.

**Fix:** delete `"push_token": PUSH_TOKEN` from `build_session_request()`.

### RANK 5 — the CTIT collapsed in run_hanaf7 (bug, class e)

`run_install.py` main() computes `wait = click_second + 88 - time.time()`
but then calls **`time.sleep(10)`** instead of sleeping the wait:

```
run_hanaf7: click t=+1s → "installing... (CTIT wall clock, 87s)" → session t=+11s
```

Server-visible click→session gap: **golden 433.5 s** (click_time
15:40:25 → session created_at 15:47:38), hanaf6 88 s, **hanaf7 11.25 s** —
an implausibly fast "Play install" for a loan app. hanaf6 (88 s, plausible)
still went Organic, so this alone is not the cause — but it must be restored
before any clean A/B.

**Fix:** `time.sleep(max(0.0, click_second + 88 - time.time()))`.

### RANK 6 — `click_time` is stamped BEFORE the click happens (story-sign flip)

main() captures `click_second = int(time.time())` **before**
`open_click_link()`, so our claimed click_time precedes the Adjust click
record (~1 s later). Genuine relationship in both captures:
`engagement_time (click record) <= click_time == click_time_server`
(golden: engagement 10:10:24Z, click_time 15:40:25 = +1 s; Pixel 6a: +2 s).
Ours is the mirror image (record after claim).

**Fix:** take `click_second` after the reftag returns
(`click_second = int(time.time()) - 1`) and set
`install_begin_time = click_time + 1 s` (golden: 25→26 s; ours currently +2 s).

### RANK 7 — field ORDER diffs (cosmetic, class e)

Wire order is HashMap-iteration order on the device; form parsing is
order-blind and the adj7 law is key-based, so this cannot flip the verdict —
listed for byte-fidelity. All are insertion-shift effects of Ranks 3–4 plus
two real placement diffs:

- session: golden `partner_params` at position 5 (right after
  hardware_name); ours at 31 (after push_token).
- session: golden `initiating_package_name` at position 40 (between
  package_name and os_name); ours at 32 (after partner_params).
- sdk_click: golden `partner_params` at position 4 (right after
  app_version); ours at 16 (after install_version).

**Fix:** move `partner_params` after `hardware_name` (session) / after
`app_version` (sdk_click); move `initiating_package_name` between
`package_name` and `os_name` (session).

### RANK 8 — the golden flow's POST /event is skipped (class e, post-verdict)

Golden sid 45: POST /event ~2 s after the attribution answer — 48 fields
incl. `event_token=y3sjx5`, `event_count=1`, `seq=1`,
`callback_params={"google_adid":"<gaid>"}`, `session_length=5`,
`time_spent=5`, partner_params. Fires AFTER the verdict, so it cannot cause
Organic; add for full-flow fidelity (the app's first-open event).

### Non-blocking observations

- **Request line form**: golden uses absolute-form
  (`POST https://app.adjust.com/session HTTP/1.1` — the phone was proxied
  through Fiddler); http.client sends origin-form (`POST /session`). The
  booked answer reproduces over origin-form (REPLAY_RULE_RESULT probe G),
  so the server is form-blind. Informational.
- `partner_params` payload: golden `4c2576c7-56da-3568-9d9c-dd5ef029b6c8`
  (uuid-v5-shaped) vs ours v4 random — per-install random by design; shape
  and encoding identical.
- `installed_at`/`updated_at`: golden click+41.6 s (real download finish)
  vs ours click+63.8 s — plausible-value-only.

---

## 2. Concrete change list for run_install.py

1. `build_click_request()`: ADD `"click_time_server": _stamp(click_sec, 0)`
   (same value as click_time) and `"install_begin_time_server":
   _stamp(begin, 0)` (same as install_begin_time); place after
   `screen_format` / after `google_play_instant` respectively (golden wire
   positions).
2. `build_click_request()`: REMOVE `"initiating_package_name"`.
3. `build_session_request()`: REMOVE `"push_token"`; MOVE `partner_params`
   to directly after `hardware_name`; MOVE `initiating_package_name` to
   directly after `package_name`.
4. `build_click_request()`: MOVE `partner_params` to directly after
   `app_version`.
5. `DEVICE`: switch to the golden moto g42 profile (IN / 31 / 12 / moto g42
   / motorola / S2SE32.28-28-4 hardware+build / 1080x2237) and align
   `BROWSER_UA` to `(Linux; Android 12; moto g42)` so click and app tell
   one device story.
6. `main()`: `time.sleep(max(0.0, click_second + 88 - time.time()))`
   (restore the full CTIT; kills the hanaf7 11 s bug).
7. `main()`: set `click_second` AFTER the click chain returns
   (`int(time.time()) - 1`), and `install_begin_time = click_time + 1 s`.
8. Optional (fidelity): after a non-organic attribution, POST /event
   (event_token y3sjx5, seq=1, event_count=1, callback_params google_adid,
   partner_params, session_length/time_spent ≈ seconds since session).

After 1–4 + 7 the sdk_click wire shape is field-for-field identical to the
golden's; after 5 the three requests are value-identical except the fields
that are per-install by design (gaids/uuids/timestamps/reftag/partner uuid).

## 3. Honest unknowns

- The click itself (mobpine → adjust click → reftag issuance) is not in the
  SAZ and cannot be diffed from the capture; the golden click happened on
  the phone before capture began. Its server-side record is proven alive
  (probe G replays the booked verdict), so the funnel's fresh clicks DO
  create records — the failing join is on the sdk_click side.
- Whether Ranks 1–6 individually or jointly flip Organic → booked is not
  provable offline; the sdk_click pair (Rank 1) plus the device-story
  consistency (Ranks 2/5/6) are the only remaining client-side differences
  a validator can see.
