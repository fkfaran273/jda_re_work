# FUNNEL PARAMS vs GOLDEN byte audit — `run_fix1.py` vs `golden_raw/`

Scope: `adj7/work/myrun/run_fix1.py` (funnel copy under test) against golden ground
truth `adj7/work/booking_diff/golden_raw/{42,43,44,45}_{c,s}.txt`
(genuine moto g42 requests that booked NON-ORGANIC 248wk8ym) and the prior
ranked diff `adj7/work/booking_diff/BOOKING_DIFF.md` (read first; every item
below was RE-verified by direct inspection/execution, not trusted).
Offline only; no traffic to app.adjust.com was sent. All `run_fix1.py`
line refs are 1-based.

Method: imported the copy's builders in-process (no network calls), pinned
`PARTNER_PARAMS` to the golden uuid, and diffed key SET, key ORDER
(position-by-position), and value SHAPE against the golden wire bodies/query.
Transport (`call()`), percent-encoding, `_fill_device_id`, constants, and
timestamp logic were each exercised directly.

## 0. Headline result

**Key SET diff: zero on all four messages. Key ORDER diff: zero on all four
messages (verified position-by-position, programmatic).** All eight
BOOKING_DIFF field fixes (Ranks 1, 3, 4, 7) plus the device profile (Rank 2),
click orientation (Rank 6), CTIT sleep (Rank 5), and first-open event
(Rank 8) are confirmed present in this copy:

| message | golden fields | copy fields | set diff | order diff |
|---|---|---|---|---|
| POST /session (42) | 45 | 45 (`build_session_request`, `run_fix1.py:304-333`) | none | none — 00..44 identical |
| POST /sdk_click (43) | 49 | 49 (`build_click_request`, `run_fix1.py:267-301`) | none | none — 00..48 identical |
| GET /attribution (44) | 22 | 22 (`build_attribution_request`, `run_fix1.py:336-350`) | none | none — 00..21 identical |
| POST /event (45) | 48 | 48 (`build_event_request`, `run_fix1.py:353-383`) | none | none — 00..47 identical |

Server twins present and equal in the copy: `click_time == click_time_server`
(`run_fix1.py:280,293`), `install_begin_time == install_begin_time_server`
(`run_fix1.py:295,298`), `installed_at == updated_at` in session
(`run_fix1.py:309,321`) and click (`run_fix1.py:270,292`) — same equalities
as golden. `initiating_package_name` is session-only at position 40
(`run_fix1.py:330`, golden 42 pos 40); no `push_token` anywhere (golden has
none either); `partner_params` sits right after `hardware_name` (session,
`run_fix1.py:311`, golden 42 pos 5) and right after `app_version` (click,
`run_fix1.py:275`, golden 43 pos 4; event `run_fix1.py:359`, golden 45
pos 3). `initiated_by=backend` first in attribution (`run_fix1.py:339`,
golden 44 pos 0).

## 1. Per-message value-shape audit

Timestamp FORMAT: identical. Every `_at`/`click_time*`/`install_begin*`
validates against `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+0530$`
(local digits + offset label; `_stamp`, `run_fix1.py:120-128`). Click twins
use ms `000` exactly like golden (`run_fix1.py:280,293-295,298` vs golden
`...25.000`/`...26.000`). ms VALUES are per-install free; recorded for
completeness (copy → golden): installed `.800` → `.629`; session
created `.198`/sent `.523` → `.430`/`.514`; click created `.252`/sent
`.263` → `.531`/`.545`; attribution created `.539`/sent `.569` →
`.741`/`.754`; event created `.280`/sent `.312` → `.343`/`.351`. Direction
invariants hold on both sides: `sent_ms > created_ms` within each request,
same second. UUID SHAPES: `gps_adid`/`android_uuid` are lowercase
`8-4-4-4-12` hex on both sides (copy generates real uuid4; verified by
regex). `partner_params` shape identical: `json.dumps(separators=(",",":"))`
(`run_fix1.py:76-77`) percent-encodes byte-exact to the golden form
(verified: `quote_plus` output `==` golden
`%7B%22payrupik_c_id%22%3A%22…%22%7D`). `callback_params`
`{"google_adid":"<gaid>"}` shape identical (`run_fix1.py:378`). Referrer
shape identical when the live reftag is present: `quote_plus` of
`adjust_reftag=…&utm_source=…&utm_campaign=…&utm_content=…` reproduces the
golden byte string exactly (verified `==`); reftag trail has no sub2/zt1
suffix on either side.

## 2. Transport (`call()`, `run_fix1.py:394-421`)

- Header SET and ORDER: identical to golden on both methods. POST:
  `Client-SDK, Authorization, Content-Type, User-Agent, Host, Connection,
  Accept-Encoding, Content-Length` (last) — `run_fix1.py:404-413` emits in
  exactly this order. GET: same minus Content-Type/Content-Length
  (`run_fix1.py:406,412` both gated on `body is not None`) — matches golden
  44 (6 headers). No diff.
- `Content-Type` exact value `application/x-www-form-urlencoded`, no
  charset (`run_fix1.py:407`) — matches golden 42/43/45. No diff.
- `Content-Length`: `str(len(body))` over the urlencoded bytes
  (`run_fix1.py:413`) — correct construction; golden headers equal their
  body bytes (1124/1420/1114). No diff (live lengths will differ only
  because per-install values differ in length, e.g. uuid constant length —
  actually fixed length; reftag length varies).
- Percent-encoding: POST body uses `urlencode(fields)` = `quote_plus`
  default (`run_fix1.py:395`); GET query uses
  `urlencode(fields, quote_via=quote)` (`run_fix1.py:396-397`). Verified by
  execution: `moto g42` → `moto+g42` (POST, matches golden 42/43/45) vs
  `moto%20g42` (GET, matches golden 44); `:`→`%3A`, `+`→`%2B` identical in
  both encoders. No diff.
- Dict insertion order is preserved onto the wire (`urlencode` iterates the
  dict; py3.7+ order-stable) — confirmed by the zero order diffs in §0.
  No diff.
- Request-line form: golden uses absolute-form
  (`POST https://app.adjust.com/session HTTP/1.1` — proxied phone) while
  `putrequest(method, target)` (`run_fix1.py:403`) sends origin-form
  (`POST /session`). NOTE ONLY — prior replay (BOOKING_DIFF Rank-note,
  probe G) proved the server booked over origin-form. Cosmetic.

## 3. `call()` URL building — confirmed

GET query `quote` (space `%20`), POST body `quote_plus` (space `+`) —
`run_fix1.py:395-397`, execution-verified in §2. Insertion order preserved
(§0). No diff.

## 4. Click chain

- `_fill_device_id` (`run_fix1.py:182-193`): exercised with 18 variants —
  `adj_gps_adid=`/`gps_adid=` empty mid-query and end-query, `%7B..%7D`
  macros, raw `{..}` macros, mixed pairs, prefilled values, case variant.
  ALL PASS: empty/macro slots filled, `&` preserved via the `(&|$)` +
  `\1` backreference (mid-query `&` survives, end-query empty group is
  exact), prefilled non-empty values untouched, `(?<!adj_)` lookbehind
  prevents double-filling `adj_` params (the backreference fix holds).
  Lookup is case-sensitive (`Adj_Gps_Adid=` untouched — correct, wire
  params are lowercase).
- Micro-edges (cosmetic, no golden counterpart — the click is not in the
  SAZ): lowercase `%7b..%7d` does not match (uppercase-only patterns);
  double-encoded `%257B` not handled; `open_click_link` macro strip
  (`run_fix1.py:220-221`) only handles the `&ip_address=` (non-first-param)
  position.
- LINK template (`run_fix1.py:65-66`):
  `http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498&sub3={gaid}`.
  UNVERIFIABLE against golden (click predates capture by design). Two
  observations: (a) the template carries NO `gps_adid`/`adj_gps_adid`
  parameter, so the adjust hop depends entirely on the fallback append
  `url += "&gps_adid=" + gaid` (`run_fix1.py:200-201`) plus per-redirect
  `_fill_device_id` (`run_fix1.py:222`) — whether the adjust hop expects
  bare `gps_adid` or `adj_gps_adid` cannot be confirmed offline (see D8);
  (b) `_subst` (`run_fix1.py:137-140`) maps `{sub2}`→`zt1`, but LINK has no
  `{sub2}` placeholder — dead branch; golden referrer has no sub2 either,
  so no wire effect either way.
- `_reftag_in` (`run_fix1.py:143-148`): `referrer=` split, `unquote`
  (`run_fix1.py:146`), `;S.browser_fallback_url` cut (`run_fix1.py:147`) —
  matches the golden referrer trail shape. BUG (cosmetic): the
  `&ip_address=%7B[^&]*%7D` strip (`run_fix1.py:148`) runs AFTER unquoting,
  so it can never match (post-unquote the text contains `{loop_id}`, not
  `%7Bloop_id%7D`) — verified by execution: the macro leaks through
  `_reftag_in`. The `Location` path is still safe (pre-stripped in both
  forms at `run_fix1.py:220-221` before `_reftag_in` is called), but the
  text-body path (`run_fix1.py:228-231`) and the market:///intent:// path
  (`run_fix1.py:204-210`) call `_reftag_in` without pre-strip, so a macro
  there would leak into the `referrer` param. No golden counterpart to
  compare; low risk (mobpine macro observed on `Location` only).
- Chain behaviour (`open_click_link`, `run_fix1.py:196-244`): 2 attempts ×
  12 hops, `Location`/`location` case pair (`run_fix1.py:216`),
  `location.replace("…")` JS-hop extraction (`run_fix1.py:232-240`), 2 s
  inter-attempt sleep (`run_fix1.py:243`). Behaviour only, no golden
  counterpart. The chain DOES carry `gps_adid=` on every hop it touches
  (fill + fallback append) — the join-critical property.

## 5. Constants — all confirmed literally in the copy

| literal | golden | copy | ref |
|---|---|---|---|
| app_token `smxi7gqwu39c` | 42/43/44/45 | exact | `run_fix1.py:35` |
| cert `c1bfafcaffb8…2c6df` (full `c1bfafcaffb84b805288b985fbe48e7f33d2c6df`) | auth claims (via signatures) | exact | `run_fix1.py:37` |
| client_sdk `android5.6.0` | hdr 42/43/44/45 | exact | `run_fix1.py:36` |
| `adj_signing_id=1300000` | Authorization 42/43/44/45 | exact | `run_fix1.py:38` |
| `algorithm=adj7` | Authorization | exact | `run_fix1.py:39` |
| `headers_id=8` | Authorization | exact | `run_fix1.py:40` |
| `native_version=3.62.0` | Authorization | exact | `run_fix1.py:41` |
| event_token `y3sjx5` | 45 pos 32 | exact | `run_fix1.py:374` |
| `initiated_by=backend` | 44 pos 0 | exact | `run_fix1.py:339` |
| moto g42 profile (IN/31/12/motorola/S2SE32.28-28-4/1080×2237) | 42/43/44/45 values | exact | `run_fix1.py:53-63` |
| `APP_UA Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)` | hdr 42/43/44/45 | exact `==` golden | `run_fix1.py:109-110` |
| `BROWSER_UA (Linux; Android 12; moto g42) … Chrome/131.0.0.0 …` | (no golden click) names the same device as the app | fixed | `run_fix1.py:84-85` |

(`sign()` passes the campaign dict straight into `mint_adj7` with
`include_block2=True`, `run_fix1.py:386-391`; per-request `kind` strings
`session`/`click`/`attribution`/`event` are internal and were proven
byte-exact by prior replay — not re-verifiable offline, no evidence of a
diff.)

## 6. Timestamp logic

- `_stamp` local-offset math (`run_fix1.py:120-128`):
  `datetime.fromtimestamp(ts + off, utc)` + `Z+0530` label ⇒ local digits +
  offset label, matching the golden convention on every field. Verified
  output shape `1970-01-01T05:30:00.000Z+0530` for `ts=0`. No diff.
- `MINT_SKEW = -2` (`run_fix1.py:112`, `signing_second`
  `run_fix1.py:116-117`): every request's `created_at`/`sent_at` AND its
  auth timestamp derive from the same `sec = now − 2`, so auth and fields
  are mutually consistent (single signing second per request — confirmed at
  `run_fix1.py:478-481,498-502,512-514,538-541`). Server-visible effect:
  claimed send time trails arrival by ~2 s (golden transit ≈ 0.5 s:
  sent `15:47:38.514` vs server `Date: 10:17:39 GMT` = `15:47:39+0530`).
  A ~2 s transit is plausible (queue/network) — cosmetic/low.
- `click_second` placement (`run_fix1.py:445`): `int(time.time()) − 1`,
  taken AFTER the click chain returns — the Rank 6 fix holds (claimed
  `click_time` no longer precedes the Adjust click record). Residual
  approximation: golden record→claim delta is +1 s (`engagement_time`
  `10:10:24Z` vs `click_time` `15:40:25+0530` = `10:10:25Z`); the copy's
  delta equals chain-duration-dependent timing (claim = chain-end − 1),
  so a slow chain yields a larger record→claim gap. Direction correct,
  magnitude approximate — cosmetic.
- `install_begin = click + 1 s` (`run_fix1.py:271,298`) — matches golden
  (`25→26 s`). `INSTALL_AFTER = 42` (`run_fix1.py:67`): copy installed =
  click + 42 s vs golden click + 41 s (`15:40:25→15:41:06`) — 1 s overshoot
  plus free ms (`.800` vs `.629`). Trivially adjustable to 41; booking
  relevance unlikely (1 s inside install-duration noise) — cosmetic.
- CTIT wait math (`run_fix1.py:469-474`): `target = click_second + 88`,
  `sleep(max-sleep wait)` — full 88 s CTIT restored, Rank 5 bug gone. But
  the golden story is much slower: click→session 433 s
  (`15:40:25→15:47:38`), install→session (first-open delay) 392 s
  (`15:41:06→15:47:38`). The copy's install→session gap is 46 s (42→88).
  88 s is a plausible install story (and hanaf6's 88 s was deemed plausible
  in BOOKING_DIFF), but it remains ~5× faster than this golden's 433 s —
  the largest remaining storytiming gap. Booking-relevant (unknown
  weight; velocity/install-duration signals are server-side heuristics).
- Session→click 50 ms (`run_fix1.py:496-497`): golden gaps are session
  created→click created 101 ms (`38.430→38.531`), sent→sent 31 ms
  (`38.514→38.545`). The copy's 50 ms sleep plus network RTT lands in the
  same neighbourhood. Second-boundary race (cosmetic): session `sec`
  (`run_fix1.py:478`) and click `sec_ck` (`run_fix1.py:498`) are separate
  `signing_second()` calls with RTT + 50 ms between them, so a midnight-
  style second tick can put click `created_at`/`sent_at` one second after
  session's (golden: same second `38`). Rare, tiny.
- Attribution +2.8 s (`run_fix1.py:511`): golden session created
  `38.430` → attribution created `41.741` = +3.3 s. Copy equivalent ≈
  2.8 s + RTT. Same shape. No diff.
- Event +2.1 s (`run_fix1.py:537`), `session_length=5`/`time_spent=5`
  (`run_fix1.py:371,375`): golden event created `43.343` = session created
  `38.430` + 4.9 s ≈ 5 — and the copy's event likewise fires ≈ 5 s after
  its session (88 → ≈93), so the hardcoded `5` is consistent in the
  no-poll path. CONDITIONAL (cosmetic): on an Organic verdict the +30 s
  confirmation poll (`run_fix1.py:520-530`, a second attribution GET the
  golden never sends — post-verdict, first verdict unaffected) pushes the
  event to ≈ +35 s after the session while it still claims
  `session_length/time_spent = 5`. Post-verdict only.
- No impossible story anywhere: `created ≤ sent ≤ arrival` holds per
  request; `click ≤ begin (click+1) ≤ installed (click+42) ≤ session
  (click+88)` is monotonic; `installed == updated`; twins equal. The only
  numerically "impossible" candidate ever present (click claimed before
  the click record) is fixed.

## 7. Prior-diff re-verification ledger (BOOKING_DIFF.md §1–2)

- RANK 1 (server-time pair): FIXED — `click_time_server` pos 36,
  `install_begin_time_server` pos 39, values equal to twins
  (`run_fix1.py:293,295`); golden positions 36/39 identical.
- RANK 2 (device/geo): FIXED — DEVICE is the moto g42/IN/api31 profile
  (`run_fix1.py:53-63`); `APP_UA` byte-equals golden; `BROWSER_UA` names
  the same device. (Dead `CLICK_UA`, `run_fix1.py:72-73`, still names the
  old GM1901/Android 10 profile — unused; see D12.)
- RANK 3 (`initiating_package_name` on click): FIXED — absent from
  `build_click_request`, present session-only pos 40.
- RANK 4 (`push_token` on session): FIXED — absent from builders; the
  `PUSH_TOKEN` constant (`run_fix1.py:74-75`) is now dead code.
- RANK 5 (CTIT `sleep(10)`): FIXED — full-wait sleep (`run_fix1.py:470-474`).
- RANK 6 (click stamped before click): FIXED — `click_second` after chain
  (`run_fix1.py:445`), `install_begin = click + 1`.
- RANK 7 (field order): FIXED — zero position diffs (§0), golden order
  reproduced exactly including `partner_params`/`initiating_package_name`
  placements.
- RANK 8 (event skipped): FIXED — `build_event_request` 48/48 key- and
  order-identical to golden 45, sent +2.1 s after attribution
  (`run_fix1.py:535-544`).
- CORRECTION to BOOKING_DIFF: the golden `partner_params` uuid
  `4c2576c7-56da-3568-9d9c-dd5ef029b6c8` is NOT "uuid-v5-shaped" — its
  version nibble (third group `3568…` → `3`) is neither v4 (`4`) nor v5
  (`5`). What matters (8-4-4-4-12 lowercase hex) matches the copy's uuid4
  at pattern level; the nibble is per-install random either way.

## 8. FINAL LIST — exact remaining diffs, no matter how small

Booking-relevant (server-visible):

- D1. CTIT story 88 s vs golden 433 s (install→session 46 s vs 392 s).
  `run_fix1.py:67,469-474`. Plausible but 5× faster than this golden.
- D2. `INSTALL_AFTER = 42` vs golden 41 s (1 s overshoot; ms `.800` vs
  `.629` free). `run_fix1.py:67,270,306`.
- D3. `MINT_SKEW = -2` staleness: fields + auth consistently ~2 s old at
  arrival (golden transit ~0.5 s). `run_fix1.py:112,116-117`.
- D4. `click_second = chain-end − 1` (`run_fix1.py:445`): record→claim
  delta approximate (golden +1 s; copy varies with chain duration).
- D5. Session→click gap has a second-boundary race (separate `sec` calls,
  `run_fix1.py:478` vs `498`); golden same-second. Rare/tiny.
- D6. Organic-path +30 s attribution re-poll (`run_fix1.py:520-530`): an
  extra GET the golden never sends; post-verdict only, but it also makes
  the subsequent event's `session_length/time_spent = 5` understate the
  wall (~35 s) when the poll fires. `run_fix1.py:371,375,522-524,539`.
- D7. Click-hop device-id parameter name unverifiable: LINK has no id
  param and the fallback appends bare `gps_adid=`
  (`run_fix1.py:65-66,200-201`); the golden click is absent from the SAZ,
  so whether the adjust hop must carry `adj_gps_adid=` (which `_fill`
  also supports on redirects, `run_fix1.py:187,189,191`) is unconfirmed.
- D8. Proxy asymmetry when `FUNNEL_PROXY` is set: click hops honour it
  (`run_fix1.py:157-163`), app traffic in `call()` does not
  (`run_fix1.py:398`) — click vs app egress IP could diverge. No effect
  when the env var is unset.

Cosmetic (wire-identical or code-only):

- D9. Zero key set/order diffs on all four messages (§0 table) — i.e. the
  previously ranked field diffs are gone.
- D10. Transport identical except request-line form (origin vs absolute —
  proven form-blind). `run_fix1.py:394-421`.
- D11. Encoding correct both ways (POST `+`, GET `%20`), order preserved.
  `run_fix1.py:395-397`.
- D12. `_reftag_in` `ip_address` strip dead post-unquote
  (`run_fix1.py:143-148`); leaks only via text-body/market paths, golden
  has no such suffix. Real code bug, negligible wire risk.
- D13. Dead code: `CLICK_UA` stale profile (`run_fix1.py:72-73`),
  `PUSH_TOKEN` (`run_fix1.py:74-75`), `build_tps_request`
  (`run_fix1.py:248-264`), `_proxied` helper (`run_fix1.py:102-107`),
  `{sub2}` branch in `_subst` (`run_fix1.py:137-140`), unused `click_sec`
  param in `build_event_request` (`run_fix1.py:353`) — the last is
  correctly unused (golden event carries no install echo).
- D14. Stale docstrings/comments only: module docstring
  (`run_fix1.py:2-14`: "43/44 fields", "19 params", "63.8 s CTIT"),
  `build_click_request` "47 fields" (`run_fix1.py:268`, now 49),
  `build_session_request` "46 fields" (`run_fix1.py:305`, now 45),
  install-timing comment (`run_fix1.py:466-468`). No wire effect.
- D15. Click-side fingerprint (`BROWSER_HEADERS`, `run_fix1.py:86-99`:
  `Accept-Encoding: identity`, `Connection: close`, Sec-Fetch-*) and the
  2×12-hop retry behaviour (`run_fix1.py:196-244`) have no golden
  counterpart — note only.
- D16. `_fill_device_id` micro-edges: lowercase `%7b`, double-encoded
  `%257B`, first-param `?ip_address=` strip. Note only.
- D17. Golden server-side reference (no copy diff possible offline):
  `42_s`/`43_s`/`45_s` → `{"app_token","adid:6b575c41…","ask_in":2000
  (session only)}`; `44_s` → NON-ORGANIC `248wk8ym /
  VL-Alliance::HM2::HM2_1722_`, `engagement_time 2026-10-06T10:10:24Z`
  (= `click_time` − 1 s), server `installed_at`/`first_session_time`
  `10:17:39Z` (= session receipt). The copy obtains fresh values live.

Bottom line: the funnel copy is now field-for-field and order-for-order
identical to the golden on every message, with correct twins, encoding,
headers, constants, and timestamp shapes. What remains is per-install
randoms (uuids/ms/reftag/adid), second-scale story timings (D1–D6), the
inherently unverifiable click-hop details (D7, D15), a proxy config trap
(D8), and dead/stale code (D12–D14). Nothing in the remaining list has the
profile of the old always-Organic join failure (missing server-time pair /
wrong device story), which are both verified fixed.
