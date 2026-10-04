# Request parity achieved — and the gate is still not in the request

**Date:** 2026-09-24
**Follows:** `H_REFUTED_RESULT.md`

## What changed

With the envelope exonerated (H-independent, byte-exact vs the app), the only
remaining place the app and our script could differ is the request itself. So I
extracted every distinct request from the real app capture `attrq2.txt` and
diffed it field-by-field against what our builders emit.

Five distinct app requests were recovered (22/43/47/46/42 params), representing
`/attribution`, `/session`, and `/sdk_click`.

### The one real defect found: `mcc`/`mnc`

```
SESSION: ours=45 app=43
  EXTRA (we send, app doesn't):
     - mcc = 404
     - mnc = 10
CLICK:   ours=49 app=47
  EXTRA (we send, app doesn't):
     - mcc = 404
     - mnc = 10
```

`FC.DEV` carries SIM network codes, and `no_sim` was unset, so they leaked into
every request. The real app sends them **zero times** across both full captures
(`attrq.txt` and `attrq2.txt` — `grep -c "mcc=" = 0` in both).

This is a genuine fingerprinting tell: a real Android device on this Play
install has no SIM operator codes in its Adjust traffic, and ours did.

Fixed in `mint_pipeline.py` — all three builders (`api_session_mint`,
`api_sdk_click_mint`, `api_attribution_mint` region) now unconditionally drop
`mcc`/`mnc` rather than only under `no_sim`.

### Parity after the fix

```
SESSION: ours=43 app=43  missing=none  extra=none
CLICK:   ours=47 app=47  missing=none  extra=none
```

Exact key-set parity on both endpoints, verified against the real capture.
Selftest passes (192-B blob, byte-identical remint, L1/L2/L3 structural laws).

### A correction to my own earlier reading

My first diff reported the session as badly wrong — claiming we send
`source=install_referrer`, `referrer`, `click_time` and are missing 8
Play-install fields. That was my error: I diffed against `S2P` (the install
template) when the session builder correctly uses `S1P`. The session was never
broken. The only genuine difference was `mcc`/`mnc`.

## Result: still Organic

Live run with the corrected params, device egress, device click, real CTITs:

```
CTIT 6s   poll 1..5  token=wy7261z network=Organic eng=0001-01-01 => organic
CTIT 30s  poll 1     token=wy7261z network=Organic eng=0001-01-01 => organic
```

Still Organic. So the gate is not the wire params either.

## Where the gate is NOT (now established by experiment)

| Candidate | Status | Evidence |
|---|---|---|
| Transport / egress IP | Refuted | device egress, still Organic |
| CTIT timing | Refuted | 6s (real), 30s, 120s, 217s all Organic |
| The 192-byte envelope | Refuted | H-independent; we mint it byte-exactly |
| key2 / arg3 H | Refuted | `d4`/`d0` recoverable from 4-byte `d2`, 6/6 |
| Wire param set | Now at exact parity | 43/43 and 47/47, still Organic |

Every difference I can construct between our request and the app's is now
eliminated, and the verdict is unchanged. That is a meaningful negative: the
remaining difference cannot be a field in the request we send.

## What this points at

The app and our script now send the same endpoints, the same param keys, the
same headers, a byte-exact signature, from the same device, same GAID, same IP,
same timing — and get different verdicts. The remaining explanations are
**state the server holds that our path never establishes**, not data we compute:

1. **The Play Store install referrer chain.** The app's install arrives with
   `initiating_package_name=com.android.vending` and a real Google Play
   install referrer. Our script *asserts* those fields; it does not pass
   through an actual Play install. The server can cross-check the referrer
   against Play's own record of that install.
2. **GAID issuance history.** We write a chosen GAID into the GMS prefs file
   (`arm_transport2.set_gaid`). The app's GAID was genuinely issued by Play
   Services for that install.
3. **Server-side click record.** Our click is fired from `curl` on the device,
   not from a Play-referrer-mediated flow.

Point 1 and 2 are the same underlying thing: the click and the install are only
linked server-side if the *install itself* was attributed to that click by
Google Play. Both are external to the signature, and neither is reproducible by
minting a better blob.

## Files

- `audit_pairs.py` / `audit_pairs_result.json` — proves pair_h3 rows 2,3 mispaired
- `h_invariant_test.py` — the decisive H-invariance test (6/6)
- `app_reqs.json` — all five app requests extracted from `attrq2.txt`
- `mint_pipeline.py` — `mcc`/`mnc` removed from all three builders
- `H_REFUTED_RESULT.md` — the H refutation
