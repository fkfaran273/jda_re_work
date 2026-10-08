# ORDERFIX_RUN.md — adj7 field-order fix: verification + one live cycle
Date: 2026-10-08 (run 01:52–01:54 local)

## 0. What was wrong and what was corrected

The just-applied fix (`_DEVICE_ORDER` + `_reorder()` + partner_params re-enable)
had two residual defects, found by the offline byte-order verification:

1. **partner_params still suppressed.** `CAMPAIGN` carried
   `"partner_params_session": None` / `"partner_params_click": None`.
   `PP_SESSION = CAMPAIGN.get("partner_params_session", PARTNER_PARAMS)`
   returns the *stored* `None` (the key exists), so the default payrupik
   `PARTNER_PARAMS` never applied — session stayed at 44 fields and click at 48,
   the exact 44-vs-45 bug the patch meant to fix.
   **Fix:** removed both `None` entries from `CAMPAIGN` (absent -> default
   `PARTNER_PARAMS` applies), with a comment so it does not regress.
2. **sdk_click was never reordered.** `call()` mapped `"/sdk_click"` to kind
   `"click"`, but the `_DEVICE_ORDER` table key is `"sdk_click"` —
   `_reorder(fields, "click")` found no order and returned fields unchanged.
   (Session and attribution were unaffected.)
   **Fix:** `call()` kind map now `"sdk_click": "sdk_click"`.

The attribution GET handling was checked and is correct as applied: in `call()`
the `elif kind == "attribution"` branch reorders the fields *before* the query
string is built (`url = path + "?" + urlencode(fields)`).

## 1. Offline verification (no network)

Method: for each kind, build the request (`build_session_request`,
`build_click_request(referrer='adjust_reftag=TEST&utm_source=VL-Alliance', ...)`,
`build_attribution_request`), apply `ri._reorder(fields, kind)` with the exact
kind `call()` computes, `urllib.parse.urlencode`, split on `&`, list keys, and
compare to the device order. Device orders for click and attribution were
extracted from `C:\Users\Apps\Downloads\payruki_again_same_wifi.saz`
(`raw/42_c.txt` click POST body cut at Content-Length; `raw/43_c.txt`
attribution GET query; `parse_qsl`, first-occurrence order).

| kind        | ours (fields) | device (fields) | exact key-order match | notes                                             |
|-------------|---------------|-----------------|-----------------------|---------------------------------------------------|
| session     | 45            | 45              | TRUE                  | `partner_params` present = payrupik JSON `{"payrupik_c_id":"..."}` (PP_SESSION default applies; not None/False) |
| click       | 49            | 49              | TRUE                  | device order from raw/42_c.txt; `partner_params` at device position 5 |
| attribution | 22            | 22              | TRUE                  | device order from raw/43_c.txt (GET query)        |

Signature checks:
- `ri.sign(reordered_session, 'session', sec)` -> 304-B blob inside the header;
  `oracle.adj7_oracle.parse_device_blob(auth)['tag_ok'] == True`.
- Signer proven **order-independent**: with the same forced `nonce12`,
  `mint_adj7(..., original) == mint_adj7(..., reordered)` (claims are built by
  name from the fixed CLAIM_POOL, not dict iteration order). So the signature
  minted in `main()` before the reorder is valid for the reordered wire body.
  (`mint_adj7` is non-deterministic — random nonce per call — which is why naive
  same-dict comparisons differ.)

Result: **ALL OFFLINE CHECKS PASS** after the two corrections above (before them:
session 44/45 MISSING partner_params, click 48/49 via both kinds, attribution 22/22 OK).

## 2. Live cycle (exactly ONE click, ONE cycle, no retries)

Step a — fresh click (real installed Chrome via `browser_click.py`):
```
url      http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498&sub3=8d011e77-f13c-4b6f-9e4d-5d74ef9d772f
REFTAG   adjust_reftag=c5kFJycWSC7Z6&utm_source=VL-Alliance&utm_campaign=HM2&utm_content=HM2_1722_
CLICK_SEC=1791404569
preclick3.env: referrer=<val> gaid=8d011e77-f13c-4b6f-9e4d-5d74ef9d772f click_server_sec=1791404569
```

Step b — `FUNNEL_ASK=sdk FUNNEL_GAID=8d011e77-f13c-4b6f-9e4d-5d74ef9d772f
FUNNEL_REFTAG=<above> FUNNEL_CLICK_SEC=1791404569 FUNNEL_CIT=30 python -u
run_install.py > run_orderfix.log 2>&1`

Full verdict log (`run_orderfix.log`):
```
campaign  in.hanafintech / smxi7gqwu39c (adj7, signing id 1300000, headers 8, native 3.62.0)
device    motorola moto g42 (Android 12, api 31)
signer    adj7_pure (pure Python, cert c1bfafcaffb8...)
[01:53:02] ==============================================================================
[01:53:02] ADJ7 INSTALL FUNNEL  app=in.hanafintech  gaid=8d011e77-f13c-4b6f-9e4d-5d74ef9d772f
[01:53:02] click: http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498&sub3=8d011e77-f13c-4b6f-9e4d-5d74ef9d772f
[01:53:02] ==============================================================================
click    reftag adjust_reftag=c5kFJycWSC7Z6&utm_source=VL-Alliance  [t=+0s]
[01:53:02] installing... (CTIT wall clock, 29s)
signing  /session ...  45 fields, blob 304 B  [t=+29s]
signing  /sdk_click ...  49 fields, blob 304 B  [t=+30s]
[01:53:33] session -> HTTP 200 adid 49e7abfddf551e14040f7d5bc8203fee
[01:53:33] sdk_click -> HTTP 200  {"app_token":"smxi7gqwu39c","adid":"49e7abfddf551e14040f7d5bc8203fee"}
attribution GET -> Organic / g0bpyt5  [t=+34s]
attribution re-ask +1.4s -> Organic / g0bpyt5  [t=+36s]
poll +3 s   -> Organic / g0bpyt5  [t=+39s]
poll +8 s   -> Organic / g0bpyt5  [t=+48s]
poll +20s   -> Organic / g0bpyt5  [t=+69s]
[01:54:11] FINAL ATTRIBUTION: {"tracker_token": "g0bpyt5", "tracker_name": "Organic", "network": "Organic", "engagement_time": "0001-01-01T00:00:00Z", "installed_at": "2026-10-07T20:23:33Z", "first_session_time": "2026-10-07T20:23:33Z", "is_reattributed": false, "is_redownload_install": false}
*** Organic / not joined ***   69s total
```

## 3. Outcome

**Organic / not joined.** The wire accepted everything — session HTTP 200 with
adid `49e7abfddf551e14040f7d5bc8203fee` issued, sdk_click HTTP 200 returning the
same adid (the reftag click reached the adid), attribution 200 on all five asks —
so the reordered 45/49-field bodies and partner_params did NOT break signature
verification. But every attribution ask returned Organic (tracker g0bpyt5).

Context for the next attempt (no retry was fired, per instructions): the code's
own notes say the fresh device bookings used click->session gaps of 204–433 s
and that flows at <=93 s answered Organic; this mandated run used
`FUNNEL_CIT=30` (~42 s click-server-second -> session). The gap remains the
leading suspect, not the field order — that is now byte-verified identical to
the device on all three request kinds.

Artifacts: `run_orderfix.log`, `preclick3.env`, `last_run.json`, this file.
