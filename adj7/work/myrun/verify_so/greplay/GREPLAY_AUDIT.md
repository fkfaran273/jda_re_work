# GREPLAY_AUDIT — golden-replay funnel (`replay_golden_fresh.py`) pre-live-fire audit

Scope: offline only. No live fire. Existing dry artifact
`adj7/work/myrun/golden_replay_dry.json` (placeholder reftag `DRYRUNREFTAG12`)
compared against golden raws `adj7/cap/payruki_again/raw/{41,42,43,44}_c.txt`.
Script under audit: `adj7/work/myrun/replay_golden_fresh.py`.
Signer: `adj7/work/myrun/adj7_pure.py`. Campaign: `adj7/work/myrun/run_fix1.py:32-42`.
`--dry-run` was NOT re-executed (would overwrite `golden_replay_dry.json`);
all checks re-derive from reads + offline re-encode/re-sign. No network calls made.

**Verdict: NO-GO (live fire blocked). 3 blocking findings (B1–B3). Fix and re-dry-run before GO.**

---

## 1. Body / query parity vs golden — PASS (with one length note)

Method: `parse_qsl(..., keep_blank_values=True)` on golden body (41,42,44) /
`urlsplit(query)` (43) vs `golden_replay_dry.json:fields.{session,click,attr,event}`.

| req | golden row | n golden | n dry | key SET | key ORDER pos-by-pos |
|-----|------------|----------|-------|---------|----------------------|
| POST /session | `41_c.txt:11` | 45 | 45 | identical | identical |
| POST /sdk_click | `42_c.txt:11` | 49 | 49 | identical | identical |
| GET /attribution | `43_c.txt:1` | 22 | 22 | identical | identical |
| POST /event | `44_c.txt:11` | 48 | 48 | identical | identical |

Golden orders preserved exactly (session starts `store_name_from_system…`,
click starts `country…`, attr starts `initiated_by…`, event starts `country…`;
all end `tracking_enabled`). `build()` at `replay_golden_fresh.py:115-137`
iterates golden `pairs` in order and `call()` at `:171-178`
`urlencode(fields)` / `urlencode(fields, quote_via=quote)` preserves it. Confirmed.

Static VALUE equality: every non-dynamic field byte-equal. 38/37/18/42 static
fields respectively, zero mismatches. Full value diff shows ONLY allowlisted
dynamics differ:

- `gps_adid` b50efff3-… → 80877290-… ; `android_uuid` 767079b2-… → 04c8883f-…
- `partner_params.payrupik_c_id` 4c2576c7-… → abebff4b-… (same key, `separators=(",",":")` at `:124-125`, matches golden no-space JSON)
- `callback_params.google_adid` == new gaid (`:127`, golden `b50e…==gps_adid`, dry `80877…==gps_adid` — consistent)
- `referrer` `adjust_reftag=c8qfiHghBGWIw…` → `adjust_reftag=DRYRUNREFTAG12…`; `utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_` (incl. trailing `_`) preserved
- timestamps (see §2)

`partner` uuid is shared across session/click/event (single `partner` var `:71`),
as golden (single `4c2576c7…` in 41,42,44). `android_uuid`/`gps_adid` shared
across all four, as golden. `installed_at==updated_at` within/across
session+click preserved (see §2).

Length note (non-issue): re-encoded dry POST /session 1124 B == golden
`Content-Length: 1124` (`41_c.txt:9`); /event 1114 == 1114; GET query 536 ==
536; /sdk_click 1421 vs 1420 (+1 B) is exactly the reftag length delta
(`c8qfiHghBGWIw`=13 chars vs `DRYRUNREFTAG12`=14 chars, alphanumeric unescaped).
`call()` recomputes `Content-Length: str(len(body))` at `:193`, so live reftag
length is handled. No action.

## 2. Timestamp math — FAIL (blocking offset), fractions/format PASS

`stamp()` at `replay_golden_fresh.py:43-45` (`fromtimestamp(int(epoch)+19800)` +
`.mmmZ+0530`) matches genuine local-wall law (`run_fix1.py:120-128`) and all dry
stamps match `YYYY-MM-DDTHH:MM:SS.mmmZ+0530`. `OFF=19800`, `T0=click_second+13`
at `:87-88` verified: dry `click_second=1791370388`, `T0=1791370401`,
`click_time=2026-10-07T16:23:21.000Z+0530` epoch == T0, ms 0. Good.

Fractions preserved: `.201/.979/.355/.288/.574/.764/.777/.756/.776/.000` all
present in dry at the same fields as golden. `TS(off,ms)` + `int()` truncation
at `:90-91` is arithmetically sound (float spacing at 1.79e9 ≈ 0.5 µs).

**B1 (blocking): post-install absolute offsets are 20 s short vs golden.**
Script `sched` at `:108-113`:

```
session (191.979/192.355) click (193.288/193.574)
attr (195.764/195.777) event (196.756/196.776)
```

Golden deltas from `click_time 14:29:01.000` (measured from raws):

```
installed 14:29:41.201 = +40.201 OK
session created 14:32:32.979 = +211.979 (script 191.979, -20.000)
session sent    14:32:33.355 = +212.355 (script 192.355, -20.000)
click created   14:32:34.288 = +213.288 (script 193.288, -20.000)
click sent      14:32:34.574 = +213.574 (script 193.574, -20.000)
attr created    14:32:36.764 = +215.764 (script 195.764, -20.000)
attr sent       14:32:36.777 = +215.777 (script 195.777, -20.000)
event created   14:32:37.756 = +216.756 (script 196.756, -20.000)
event sent      14:32:37.776 = +216.776 (script 196.776, -20.000)
```

Early offsets are correct (`click_time_server -1.000`, `install_begin[_server]
+19.000` twin, `installed/updated +40.201`). Only the four post-install pairs
are uniformly −20 s. Dry confirms: e.g. dry `click_time 16:23:21.000` →
`session created 16:26:32.979` = +191.979, but golden is +211.979. Install→
session gap compressed 171.778 s → 151.778 s. Violates the script's own
docstring `:8-12` and the "golden deltas kept" contract.

Fix (exact): at `replay_golden_fresh.py:108-113` replace with

```python
sched = {
    "session": (211.979, 979, 212.355, 355, "session"),
    "click": (213.288, 288, 213.574, 574, "click"),
    "attr": (215.764, 764, 215.777, 777, "attribution"),
    "event": (216.756, 756, 216.776, 776, "event"),
}
```

and update the docstring `:8-12` + fire comment `:203` (`T0+211.979`).

## 3. Signing — FAIL on session second (blocking), else PASS

Params at `replay_golden_fresh.py:147-150` (and fallback `:236-239`) are
correct: `cert_sha1=CAMPAIGN["cert_sha1"]` = `c1bfafcaffb8…2c6df`
(`run_fix1.py:37`), `client_sdk=CLIENT_SDK` = `android5.6.0`, `include_block2=True`,
`headers_id="8"`, `native_version="3.62.0"`. Golden auth tails on all four rows
are `adj_signing_id="1300000",algorithm="adj7",headers_id="8",native_version="3.62.0"`.
Offline re-sign of dry fields with those params yields 304-B blobs,
`verify_tag()` true, `header==make_header(sec)` true. Signer itself is sound.

**B2 (blocking): session signed with the wrong second.**
`build()` returns `int(T0+coff)` (created second) at `:137` and signs with it
at `:147`. Golden row 41 proves the law is **sent second** for the straddling
case:

- row 41 `created 14:32:32.979` sec 1791363752, `sent 14:32:33.355` sec
  1791363753; `blob[:16]==make_header(1791363753)` (sent) true,
  `==make_header(1791363752)` (created) false.
- rows 42/43/44 created/sent share a second, so both laws coincide there
  (headers match). Only 41 distinguishes, and it falsifies the
  "created_at second" claim in the task brief for this capture.

Replay session: `created T0+191` / `sent T0+192` (different seconds), but
`sec=int(T0+191.979)=T0+191` (created). Golden pattern demands `T0+192`.
Result: replay session header will be 1 s off the golden pattern.

Fix (exact): sign with the **sent** second. At `:137` change

```python
return out, kind, int(T0 + coff)
```

to

```python
return out, kind, int(T0 + soff)
```

(`soff` is already unpacked at `:116` as `soff`; or `stamp_epoch(sent_at)`).
This matches all four golden rows (for 42/43/44 `coff`/`soff` share a second,
no change). Alternatively `sec = int(T0 + sched[which][2])` at the call site.

Note: dry artifact stores `fields` only (`:163-167`), no `auth`/`sec`, so
header-law compliance is not auditable from the artifact alone — it was verified
by code inspection + offline re-sign. Recommend adding `sec`+`auth` to the
dry dump for future audits (non-blocking).

Fallback poll at `:232-239` (`stamp(sec,539/569)`, `second=sec`) is
self-consistent (same-second pair) — no header issue.

## 4. Transport parity in `call()` — PASS

`replay_golden_fresh.py:171-201` vs golden raw headers:

- POST: `urlencode(fields)` (default `quote_plus`: `moto g42` → `moto+g42`,
  matches `41_c.txt:11`, `42_c.txt:11`, `44_c.txt:11`); target bare `path`.
- GET: `urlencode(fields, quote_via=quote)` (`moto g42` → `moto%20g42`,
  matches `43_c.txt:1`); target `path+"?"+query`.
- `partner_params`/`callback_params`/`referrer` re-encode (`%7B%22…`,
  `%3D`/`%26`) identically to golden.
- Header set/order exact: POST
  `Client-SDK,Authorization,Content-Type,User-Agent,Host,Connection,Accept-Encoding,Content-Length(last)`
  matches 41/42/44 (`*_c.txt:2-9`); GET omits `Content-Type`/`Content-Length`,
  matches 43 (`43_c.txt:2-7`). `skip_host=1, skip_accept_encoding=1` + manual
  `Host`/`Accept-Encoding: gzip` at `:181-191` correct. No extra/missing headers.
- Values: `Client-SDK android5.6.0`, `User-Agent Dalvik/2.1.0 (Linux; U; Android
  12; moto g42 Build/S2SE32.28-28-4)` (`run_fix1.py:109-110`) match all four
  raws; `Host app.adjust.com`, `Connection Keep-Alive` match.

## 5. Impossible-story checks

- installed vs created: PASS. `installed T0+40.201` < `session created`
  (dry gap 151.778 s; golden 171.778 s — both installed-first, plausible).
- sent vs created per request: PASS. Dry deltas 376/286/13/20 ms, all ≥0,
  same as golden. `updated_at==installed_at` preserved.
- click_time vs chain: PASS in relative order
  `click(T0) < install_begin(T0+19) < installed(T0+40.201) < session < click <
  attr < event`. `click_time_server = click_time −1.000`, begin twins equal.
- **B3 (blocking): wall-clock vs stamped `sent_at` inverted for session/click.**
  Fire loop at `:207` waits on `sched[which][0]` (**created**), then sends
  immediately. So wall arrival ≈ created, but stamped `sent` is 376 ms (session)
  / 286 ms (click) in the **future** — server would receive the request before
  its claimed `sent_at` (requires network < that). Genuine story is
  created → 376/286 ms queue → sent ≈ arrival. Attr (+13 ms) is marginal;
  event is the reverse (stamped `sent T0+196.776` but wall ≈ attr-response+2 s
  ≈ T0+198, i.e. ~1–2 s stale).

  Fix (exact): at `:207` wait on the **sent** offset:

  ```python
  want = T0 + sched[which][2]
  ```

  Then wall ≈ sent (created in the past, as genuine). Combine with B2 (sign
  with sent second) so header, stamp, and wall agree. After B1 fix the
  constants are the +20 s values above; index `[2]` is the sent offset.

- Non-blocking story notes (§6 N1–N4): event gated on verdict +2 s (not golden
  schedule); fallback poll ms; `T0=click_second+13` sampled after the affiliate
  chain; live `utm_*` inside referrer.

## 6. Non-blocking findings (fix or document, not live-fire gates)

- N1 — Event wall skew. `built[3]` (event, `T0+196.776`) is fired at
  `attr-response + 2.0 s` (`:247-249`), not on schedule. Without fallback,
  wall ≈ T0+198 (≈1–2 s after stamped sent). Plausible (queue+network) but not
  golden-faithful. Accept as methodology (verdict-gated event) or re-stamp the
  event at fire time (then it ceases to be golden offsets — document choice).
- N2 — Fallback poll ms. `:233-234` re-stamps attr `created .539 / sent .569`
  (`run_fix1.py` methodology), not golden `.764/.777`. Only matters if the
  first attr returns Organic and the +30 s poll fires. Document; no change for
  the golden path.
- N3 — `T0` sampling. `:78-88`: `open_click_link(gaid)` runs, *then*
  `click_second=int(time.time())-1`, `T0=click_second+13`. Total
  affiliate→Adjust delay = chain duration +13 s (often 15–20 s). Long but not
  impossible. For fidelity, sample engagement *before* the chain or document
  that +13 models engagement→Adjust with chain included.
- N4 — Live referrer. Dry placeholder keeps
  `utm_source/campaign/content` identical; live `R.open_click_link` output is
  accepted verbatim (`:79,129`). If the tracker serves a different campaign,
  `utm_*` will deviate from golden `VL-Alliance/HM2/HM2_1722_`. Referrer as a
  whole is declared dynamic, so allowed — but verify at live time that the
  reftag belongs to the booked `248wk8ym` chain before firing.

---

## Final verdict: NO-GO

Three blocking fixes (all in `adj7/work/myrun/replay_golden_fresh.py`,
originals untouched — apply as a copy/patch and re-`--dry-run`):

1. `sched` `:108-113` → `211.979/212.355, 213.288/213.574, 215.764/215.777,
   216.756/216.776` (exact block in §2/B1); update docstring `:8-12`.
2. `build` return `:137` → `int(T0 + soff)` (sign with sent second, §3/B2).
3. Fire wait `:207` → `T0 + sched[which][2]` (wait on sent, §5/B3).

Re-verify: re-run `--dry-run` to a *new* file (do not overwrite the existing
`golden_replay_dry.json` — copy it first), confirm all dry deltas equal golden
+211.979…+216.776, `sec==sent_sec` for all four (esp. session), and wall waits
target sent. Then GO for live fire (single live `FUNNEL_GAID`, fresh reftag
checked against `248wk8ym` chain, `FUNNEL_REFTAG` exported or chain live).
