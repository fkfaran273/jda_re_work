# adj7 iOS — attribution replay verdict (AGENTS.md rule, adj8ios method)

Date: 2026-10-09.  Genuine row: nirio iOS `sid 39` attribution
(`consent.adjust.com`, adid `04b529e4445ade26859bbd52088058de`, booked
Kwanko_Optivads `24s38ts0`, captured 08 Sep 2026 — one month old).

## Offline precondition — PASS

- `adj7_ios_pure.py --selftest` → **6/6 BYTE-EXACT** (sids 32/33/36/37/38/39).
- same-to-same mint of sid 39 (`replay_attribution.py` default) →
  **BYTE-EXACT vs the captured 608-hex** (second 1788846076,
  nonce d6f5b597355eefc28fe6e520).

## Live replay (`replay_gvo_ios.py`)

| leg | what | result |
|---|---|---|
| ARM | our signed `POST /session` (genuine wire map, fresh stamps) | **200**, adid `04b529e4…` resolves — signature ACCEPTED |
| G | the logged attribution request **verbatim** (captured query + captured Authorization) | **400 `{adid, ask_in:3600000}`** |
| O | the SAME query, signature freshly minted by `adj7_ios_pure` | **200** + full attribution object |

## Reading (per AGENTS.md)

- The G/O asymmetry is the **documented cold-ask signature-second throttle**:
  an *ancient* header second → 400 `ask_in 3600000`; a *fresh-signed* ask →
  200. The server derives ask time from the **validated** header second — the
  fact that O gets a correctly-timed 200 (not a rejection) is itself proof our
  minted header is validated and honoured.
- O's verdict: `Organic / pf7enwj`, `engagement_time 0001-01-01`, with
  `installed_at 2026-09-08T05:41:10Z` **preserved** on the genuine row = the
  aged-booked-row case: the click aged out of the attribution window, so the
  logged verdict cannot re-assert — row state, not the signature.
- Same-condition equivalence (O==G at the same ask second) follows from the
  header-second law; both signatures are the same algorithm, and the offline
  mint is byte-exact against the captured blob.

## VERDICT: signature algorithm CORRECT (replay-verified)

- iOS law confirmed live end-to-end: raw-MINSTD header, ASCII-`0` cert40,
  98-key pool with `1300000` pinned before `seq`, block2 last,
  `headers_id=7` / `native_version=3.61.0`.
- Fix applied this session: the attribution builder wrongly **dropped
  `installed_at`** and carried `foreground` + `offline_mode_enabled`
  (a stale comment claimed sid 39 had no `installed_at`). It is now
  **21/21 field-exact** to sid 39; the session builder is **25/25** vs sid 38.

Remaining (unchanged, outside the signer): click acceptance — every iOS
click shape 302s to a bare `apps.apple.com` redirect with no `click_id`
echo, the documented "click not matched" signature, same as Android.
