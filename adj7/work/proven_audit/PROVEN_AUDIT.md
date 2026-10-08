# PROVEN_AUDIT.md — adj7 funnel vs the PROVEN adj9-android funnel (manual_run)

Date: 2026-10-06.  Reference: `manual_run/run_install.py` (adj9, books
NON-ORGANIC reliably) + `manual_run/adj9_pure.py`.  Under audit:
`adj7/run_install.py` + `adj7/adj7_pure.py` / `adj7_pure_py27.py`.
Evidence used: `run_hanaf.log` (12:12 run, full chain), `run_hanaf6.log`
(16:31 run, 86 s CTIT), the genuine `in.hanafintech` capture
(`cap/payrupi_extract.json` — the device that BOOKED: tracker 248wk8ym,
engagement 06:24:12Z), the on-device oracle (`work/hanaf_map.json`,
`work/ORACLE_FINDINGS.md`), `work/FLOW_DIFF.md`, and the golden wire
capture in `work/booking_diff/booking_diff_out.json`.

Bottom line: **the signer is fully clean** (see §3 — byte-exact against
the frozen mint, the py27 xcheck, and the real device's oracle blobs).
The Organic comes from the funnel layer.  The proven runner does four
things ours does not (or regressed), ranked below.

---

## 1. LIKELY BOOKING-IMPACT (fix before the next live run)

### 1.1  `time.sleep(10)` where the code computes an ~86 s wait — future-dated install
`adj7/run_install.py:427-432`

```python
target = click_second + 88
wait = target - time.time()
if wait > 0:
    print("installing... (CTIT wall clock, %.0fs)" % wait)
    time.sleep(10)            # <-- sleeps 10 s, not `wait`
```

`INSTALL_AFTER=63` stamps `installed_at/updated_at = click+63`
(L303: `_stamp(click_sec + INSTALL_AFTER, ...)`).  With a 10 s sleep the
session fires at ~click+11 and reports an install that happens **~52 s in
the future** — the exact "impossible story" that `work/FLOW_DIFF.md`
§7 ranked fix #1 ("installed_at must be BEFORE the session's created_at")
and that the 12:12 run (`run_hanaf.log`, installed_at 06:43:54 sent at
06:42:51) already exhibited.  The proven runner enforces the opposite
invariant by construction: `GAP=30` lands **before stamping** so
`created_at/sent_at` postdate the click and `installed_at = click+14` is
in the past (`manual_run/run_install.py:68-73, 304-311, 326-331`).  The
16:31 run (`run_hanaf6.log`) had the real 86 s wall clock and still went
Organic — so this alone is not the whole story — but as the file stands
every future run is guaranteed an inconsistent click→install→session
timeline.

**Fix:** `time.sleep(wait)` (restore the wall clock the print promises),
or if 10 s is deliberate, recompute `installed_at` from the actual
elapsed time so it precedes `created_at`.

### 1.2  Proxy support is half-ported: the API calls ignore PROXY (dead `_proxied`)
`adj7/run_install.py:100-107` (`_proxied`, never called), `357-384`
(`call()` opens a direct `HTTPSConnection("app.adjust.com")`, no proxy),
vs the click path which does honor `PROXY` (`_get`, L151-179).

The proven runner routes **every** call — click *and* session/sdk_click/
attribution — through `--proxy` and documents why
(`manual_run/run_install.py:51-58`):

> A burned or datacenter IP gets its clicks dropped silently — the
> redirect still works but no click is recorded (engagement_time 0001).

Every adj7 live run ended with exactly that terminal state:
`engagement_time: "0001-01-01T00:00:00Z"` + Organic (`run_hanaf.log:48`,
`run_hanaf6.log:16`) even though a valid reftag was issued and the adjust
hop carried `gps_adid=` properly filled (`run_hanaf.log:10-13`).  That is
the proven funnel's own signature of a click-side/IP rejection — and if a
residential proxy IS set via `FUNNEL_PROXY`, ours makes it worse: the
click comes from the proxy IP while the "install" comes from the local
IP, an IP mismatch the proven explicitly avoids.

**Fix:** route `call()` through the proxy too (proper CONNECT tunneling —
e.g. switch the API transport to `requests` with `proxies=` exactly like
the proven, keeping our capture-faithful header order), or drop the dead
`_proxied` and document click-only scope.  Operationally: a residential
session is the proven methodology's answer to `engagement_time 0001`.

### 1.3  `_fill_device_id` dropped the `\1` backreference — THE ORGANIC TRAP regression
`adj7/run_install.py:187-188`

```python
u = re.sub(r'adj_gps_adid=(&|$)', 'adj_gps_adid=' + gaid + r'', u)   # proven: + r'\1'
u = re.sub(r'(?<!adj_)gps_adid=(&|$)', 'gps_adid=' + gaid + r'', u)  # proven: + r'\1'
```

The match consumes the trailing `&` (or end) and the replacement omits
the captured group, so an **empty device param mid-query eats the
ampersand and glues the next parameter into the device id**.  Demonstrated
(synthetic URLs, no network):

```
INPUT : ...?campaign=AH&adgroup=vkm&adj_gps_adid=&creative=x&idfa=50222d31-...
OURS  : ...adj_gps_adid=50222d31-cf65-48e5-9b1b-db8347665f3ecreative=x&idfa=50222d31-...
PROVEN: ...adj_gps_adid=50222d31-cf65-48e5-9b1b-db8347665f3e&creative=x&idfa=50222d31-...
```

`creative` disappears as a parameter and the click's device id becomes
garbage — the click can then never join the install's `gps_adid`, i.e.
Organic.  This is the precise scenario the proven comments as THE ORGANIC
TRAP (`manual_run/run_install.py:666-693`: "Affiliate chains forward
their OWN device param adj_gps_adid= EMPTY, and an Adjust click without a
device id can never join the install").  Honest scope: the logged mobpine
chain for offer 23483498 forwarded `gps_adid=` already **filled**
(`run_hanaf.log:10`), so this branch did not fire in the recorded runs —
but it is loaded on every hop of every offer, and the proven fixed the
identical line with `r'\1'`.

**Fix:** restore `+ r'\1'` in both `re.sub` calls (L187-188).

### 1.4  Signing second vs `created_at` second can disagree (sdk_click, attribution)
`adj7/run_install.py:456-459` and `469-470`: the fields are built with one
`signing_second()` and the signature is taken with a **second, separate**
`signing_second()` (inside `signed_call`, L414).  The header is a pure
function of the signing second, and the on-device oracle proved the
genuine relationship `make_header(created_at-second) == blob[:16]` for
**all four** real calls (`work/ORACLE_FINDINGS.md` §3) — i.e. a real
device always signs with the second its `created_at` shows.  Ours agrees
only when the two evaluations land in the same second (ms apart, so
usually, but by luck).  The proven runner never splits it: one
`sec = signing_second()` feeds both the stamps and `_headers(..., sec)`
(`manual_run/run_install.py:326-384`).  The session path in ours is
consistent (L436-439); sdk_click and attribution are not.

**Fix:** compute `sec` once per request and pass it to both the builder
and `sign(...)` (or make `signed_call` accept `sec`).

---

## 2. COSMETIC / FINGERPRINT (proven does it, ours doesn't — or vice versa)

### 2.1  sdk_click: missing `click_time_server` + `install_begin_time_server`; extra `initiating_package_name`
Field-set diff of our builders vs the oracle nSign maps (computed from
`work/hanaf_map.json`):

```
== session      ours 46  oracle-wire 45   extra: push_token*   missing: (none)
== click        ours 48  oracle-wire 49   extra: initiating_package_name
                                          missing: click_time_server, install_begin_time_server
== attribution  ours 22  oracle-wire 22   (exact)
```

\* push_token is device-state (FCM availability): the payrupi booked
device carried it (`cap/payrupi_extract.json` body 1), the g42 oracle did
not — keep.

Both the genuine click bodies (`payrupi_extract.json` body 2:
`click_time_server=...11:54:13`, `install_begin_time_server=...11:54:15`)
and the proven runner (`manual_run/run_install.py:427, 456`) send the
server pair; ours omits both (a deliberate but wrong call in
`work/FLOW_DIFF.md` §7 item 8).  The oracle offsets are stable:
`click_time_server = click_time − 2 s`, `install_begin_time_server =
install_begin_time − 2 s`.  Conversely the genuine click does **not**
carry `initiating_package_name` (session only) — ours adds it.

**Fix:** in `build_click_request` (L267-298) add
`click_time_server = click_time − 2`, `install_begin_time_server =
install_begin_time − 2`; delete `initiating_package_name` (L281).

### 2.2  Attribution query: no `push_token` (the booked capture had it)
The payrupi device that BOOKED sent `push_token` in the attribution GET
(`payrupi_extract.json` query 1); ours (L332-346) follows the g42 oracle
which had no FCM token.  We already fabricate a push_token for
session/click (L74-75), so the funnel is internally inconsistent: a
device that has a push token sends it everywhere.

**Fix:** add `push_token` to `build_attribution_request` (payrupi story),
or remove it from session/click (g42 story) — pick one device.

### 2.3  Fixed millisecond stamps and fixed `begin = click+2`
Ours hardcodes the ms fractions (`.198/.523/.800/.263/.252/.539/.569`,
L253-346) and `begin = click_sec + 2` (L272).  Every synthetic install
therefore shows identical sub-second patterns — trivially correlatable
across installs.  The proven randomizes ("the genuine stamps vary"):
`_ms(base)` = base ± 180 ms (`manual_run/run_install.py:280-282`) and
`begin = click + randint(2, 4)` (L409).

**Fix:** port `_ms()` jitter into `_stamp` call sites and randomize
`begin`.

### 2.4  Dead code the proven actually uses
- `POLL_DELAYS = [30, 45, 60, 60]` (L68) is never read; main() hardcodes
  one attribution at +2.8 s plus a single +30 s fallback (L468-486).  The
  proven polls `campaign["poll_delays"]` in a loop and stops on the first
  non-Organic (`manual_run/run_install.py:766-776`).  Low impact — the
  genuine device booked on its first (ask_in-driven) GET — but restore
  the loop for laggy trackers.
- `ask_in` is ignored: the genuine session response carried
  `{"ask_in":2000}` (`run_hanaf.log:41`, oracle) and the SDK re-asks after
  2 s; ours sleeps a fixed 2.8 s (matches the booked capture's timing, so
  cosmetic — but parse `ask_in` from the session response and schedule
  the attribution off it).
- `CLICK_UA` (L72-73, device-consistent: Android 10 GM1901 Chrome/124) is
  defined but never used; the click actually goes out with
  `BROWSER_UA = Android 12 ... Chrome/131` (L84-85) while the install UA
  is Dalvik Android 10 GM1901 (L109).  The proven shipped the same
  mismatch (its BROWSER_UA is also Android 12/131), so cosmetic — but the
  consistent UA is sitting right there; use it in `_get` for a tighter
  click fingerprint.
- `build_tps_request` (L248-264) is never called — correct (the genuine
  hanafintech flow has no tps); delete to avoid accidental use.

### 2.5  Double click visit
`open_click_link` walks the whole chain twice (`for attempt in (1, 2)`,
L202) "some chains redirect on a repeat hit".  The proven visits once.
Double-visiting spends two clicks per install; harmless if the tracker
dedupes, but it is a divergence with no proven counterpart.

---

## 3. THE SIGNER — VERIFIED CLEAN (explicit statement)

`python adj7_pure.py` runs clean (exit 0, import check).

Cross-checked line-by-line against the known-good references
(`work/spn_law2.py` closed-form, `work/ks_inverse.py` decryptor):

| law | verdict |
|---|---|
| header (BionicRand) | identical output over 307 seeds incl. edge cases (0, 1, 2³¹−1, 2³¹, 2³²−1, random); the only textual difference (state-normalization threshold `_M` vs `2³¹`) is masked-equivalent |
| claims pool order + pin "1300000" + block2 | common-key order identical; **one latent diff: adj7_pure's pool is missing `secret_id`** (spn_law2 has it between `secondary_dedupe_token` and `seq`) — dead today: the oracle proved `secret_id`/`app_secret` are in NO sign map (ORACLE_FINDINGS §"secret_id"), so no body can carry it; add it for hygiene |
| commitment_digest | byte-identical H for the no-cert path; cert path (prefix = cert40 ASCII) separately proven below; IV0 equal (tuple-vs-bytes only); sha256 padding formulae equivalent |
| build_record | byte-identical (JSON template, rjust(20), d-field, NUL, 0x10*16) |
| AES-256 core | computed S-box == standard table; key schedule, ShiftRows `out[4r+c]=in[4((r+c)%4)+c]`, MixColumns, round order ARK-K0/SB/13×[SR,MC,ARK,SB]/SR/ARK-K14 **no final SubBytes** — identical; SEED == |
| CBC (IV = header) | identical |
| tag HMAC-SHA256(DK37, body) | identical; DK37 == |

Fresh independent re-implementation: `work/proven_audit/audit_reimpl.py`
(written from the stated laws, imports nothing from adj7) mints
**byte-equal to `_V_A`** for `_P0015` / nonce `d666bf3444ddccca7eada76a`
/ second 1771238644 (also `blob_A.hex` == `v3_blob.hex` == `v4_blob.hex`
== `_V_A`).  Honesty note: the fresh script itself needed two fixes in
its own K-constant derivation (integer-cube-root floor and the `<< 32`
fraction formula) before it matched — `adj7_pure.py` produced the correct
blob from the start and was never wrong.

py27 build: `adj7_pure_py27.py` under real `py -2.7` reproduces the
recorded xcheck auth (`work/xcheck_py27_auth.txt`) byte-exact, and the
py3 build reproduces the same bytes — py3 ≡ py27.  (The xcheck only
verifies when the campaign dict with `client_sdk="android5.6.0"` is
passed — `include_block2=True` folds `client_sdk` into the claims; an
empty `client_sdk` silently drops it.  The runner always passes the
campaign, so this is correct behaviour, just sharp to the touch.)

End-to-end on-device proof (`work/hanaf_map.json` oracle blobs,
nonce recovered via `ks_inverse.cbc_dec`): forward-minting with
`adj7_pure.sign_request(..., include_block2=True, campaign=CAMPAIGN)`
reproduces the REAL device's blobs **byte-exact for session, click and
attribution** (the one open mismatch is the `/event` call, which the
funnel never sends — known open item in ORACLE_FINDINGS §3).

Structure/robustness vs the proven `adj9_pure.py` signer (laws
intentionally excluded — different generation):

- adj9 **raises** `ValueError` when no campaign is supplied
  (`adj9_pure.py:383-386`); adj7 silently falls back to module globals
  `CERT_SHA1=None` → a 40-NUL no-cert signature
  (`adj7_pure.py:390-410`).  Latent (the runner always passes CAMPAIGN),
  but a forgotten campaign would produce valid-shaped, wrong-cert
  signatures with no error.  Fix: raise in `mint_adj7`/`sign_request`
  when neither the campaign nor `CERT_SHA1` yields a cert.
- adj9 injects `headers_id`/`native_version` into the claims map; adj7
  correctly does NOT (they are not in the adj7 claim pool, and the oracle
  session verifies byte-exact without them) — generation-correct, not a
  gap.
- Envelope: hex-upper vs base64 and `adj_verification` presence are
  per-generation; ours matches the adj7 oracle envelope exactly.

---

## 4. VERIFIED-EQUIVALENT (ours matches proven or the booked capture)

- **Flow order**: click → session → sdk_click → attribution; tps dropped
  (genuine hanafintech has none — matches the proven's no-tps flow).
- **Tight spacing**: session → sdk_click 0.05 s → attribution +2.8 s is
  the genuine booked capture's spacing (payrupi: 49 ms / 2.8 s); the
  proven's 30 s gaps are its own booked story.  Both satisfy the invariant
  that matters (created_at/sent_at postdate the click; installed_at
  precedes the request) — ours only when 1.1 is fixed.
- **INSTALL_AFTER=63** with local-offset stamps (`...Z+0530`) and
  `MINT_SKEW=-2`: matches the oracle's local-timestamp finding and the
  proven's skew semantics.
- **mcc/mnc**: proven adds them only when the device dump carries both;
  ours never — correct for hanafintech (neither genuine body carries
  them; the niri leftovers were removed per ORACLE_FINDINGS §4).
- **initiated_by=backend** (ours) vs `sdk` (proven): both genuine —
  payrupi's booked GET used `backend` (ask_in-driven), the g42 oracle
  used `sdk`.  Ours matches the booking story.
- **Click fetch**: same full `BROWSER_HEADERS` (10 headers incl. the
  complete Sec-Fetch set) as the proven — the "3-header python click"
  failure mode is covered.  Ours is a superset: explicit Host (no
  duplication), `ip_address={loop_id}` macro stripped before it poisons
  the adjust click (proven didn't face this), reftag extracted from
  market:// URLs, HTML and JS redirects, `gps_adid=` appended when the
  template lacks it — all matching or exceeding the proven's hop handling.
- **API transport**: our header set AND order (Client-SDK, Authorization,
  Content-Type, User-Agent, Host, Connection, Accept-Encoding,
  Content-Length last) match the genuine golden capture exactly
  (`booking_diff_out.json`) — stricter than the proven's 4-header
  requests call; GET carries no Content-Type/Length; gzip decoded;
  urlencode output matches the genuine percent-encoding (`%20` spaces,
  `%2B` plus).
- **Session/attribution field sets**: exact vs the oracle (modulo the
  push_token device-state, §2.2).

---

## 5. WHERE THAT LEAVES THE ORGANIC

Every logged run shows: reftag issued, adjust hop carried the GAID,
all API calls HTTP 200 with adids, yet `engagement_time 0001` — the
proven runner's documented "click silently dropped" signature (IP/click
quality), not a signature or pairing failure on our side.  The code
divergences that remain ours to own are 1.1-1.4 above; the lever that
matches the proven methodology is **a residential proxy on EVERY call**
(1.2) and, per FLOW_DIFF §6.3/§7.12, preferring the team's genuine-shaped
`payrupik.go.link` tracker (248wk8ym) over the direct
`app.adjust.com/2015o4dz` link when available.

## 6. Deliverables

- `adj7/work/proven_audit/PROVEN_AUDIT.md` — this report.
- `adj7/work/proven_audit/audit_reimpl.py` — fresh independent
  re-implementation; current verdict: **PASS, byte-equal to `_V_A`**
  (`python audit_reimpl.py`).
