# AGENTS.md — standing rules for this workspace (Adjust signature R&D)

## THE ATTRIBUTION REPLAY RULE (verification law — always apply)

Whenever a signature algorithm (adj7 / adj7ios / adj8 / adj8ios / adj9 /
adj9_ios) is extracted, ported, or claimed verified, it MUST pass the
**attribution replay rule** before it counts as cracked:

> Take a genuine capture, re-send its attribution exchange through OUR
> signature making, and the server must answer the way it answered the
> genuine device in the log.

Operational form (all three probes, in this order):

1. **G — genuine control**: re-send the exact logged request bytes
   (original Authorization). This is today's baseline for the row.
2. **O — ours**: same wire map, signature freshly minted by us
   (fresh second + nonce). Must behave **identically to G** — same HTTP
   status, same adid, same tracker/network state.
3. **ARM — armed ask** (the device flow, when the row answers 4xx
   `ask_in`): our signed `POST /session` → 200 with `ask_in` → wait it →
   our signed `GET /attribution`. This is how the 200 attribution object
   is actually obtained.

Reading the results:

- **Logged verdict reproduced by O/ARM** (field-for-field) — full PASS.
  Works when the row state is stable (e.g. `unattr / No User Consent` on
  a no-consent row: watsons 2026-10-08, exact body match) or the booking
  is fresh (adj8 booking of Oct-4 replayed Oct-8).
- **Aged booked row** (click attribution window expired): the row
  re-answers `Organic` to **everyone** — the G control proves the genuine
  signature gets the same Organic (nirio 2026-10-07, lululemon 2026-10-08).
  Then the rule's signature layer is judged by **O == G** (plus the
  offline byte-exact mint). Organic-here is row state, NOT a signature
  verdict; never "fix" the signer because of it.
- **400 `{adid, ask_in}`** on a cold attribution GET = the row's ask
  cadence throttle; the genuine signature receives the identical answer.
  Not a rejection — arm via the session's `ask_in` instead.
- `/session` rate-limits ~1 per 20 min per adid (`400 request check
  interval failed`) — also not a signature failure.

The offline precondition for the rule: **byte-exact mint** of every
carved blob — tag law, record decrypt (SEED key, cert40, padding), unique
header seed inside the sent_at→wire window, claims/IV0 law, and the full
blob reproduced from (params, second, nonce12) alone. A signature that
cannot mint the capture's own bytes byte-exact is not submitted to live
replay.

## Current algorithm inventory (all replay-verified)

| folder | algorithm | platform | native | status |
|---|---|---|---|---|
| `adj7/` | adj7 | Android | 3.61–3.62 | cracked, replay-proven |
| `adj7ios/` | adj7 | iOS | 3.61.0 / 3.62.0 | cracked; 14/14 blobs byte-exact on 3 apps (watsons, nirio, lululemon); live replays: watsons verdict-exact, nirio + lululemon G==O |
| `adj8/` | adj8 | Android | — | cracked, live-booking |
| `adj8ios/` | adj8 | iOS | 3.67.0 | cracked, live-booking |
| `adj9/`, `adj9_ios/`, `adj9sign/` | adj9 | both | — | cracked, live-booking |

## Live-funnel lessons (click → install booking)

- **PERMANENCE LAW (user-proven 2026-10-08, eatr):** a consent-GATED
  (att0/att2, "No User Consent"/unattr) row keeps its stored attribution
  state **permanently** — eatr's May-15 row replayed Oct-8 returned the
  logged object verbatim, `engagement_time 2026-05-15T05:26:24Z` still
  stored 146 days later, full click deeplink trail intact. No re-evaluation
  happens without consent. So for no-consent rows, same-as-logs through
  our signature is ALWAYS achievable (watsons + eatr + PENTI all
  reproduced). A **consented** row (att3, e.g. lululemon/nirio) DOES
  re-evaluate on every ask — its booking lives only inside the
  attribution window and then answers Organic (genuine identical); and a
  row that got REINSTALLED (hunch, Oct 2) starts a new epoch, replacing
  the old state. Cold GET 400 `{adid, ask_in}` = ask throttle only —
  arm via signed session → ask_in → attribution GET to read the row.
- **Consented rows (att3, idfa present) answer LIVE re-evaluation, not a
  stored read** (nirio + lululemon, re-checked 2026-10-08 with armed
  reads): their logged BOOKED verdict is reproducible only while the
  click is inside the attribution window; after that any ask evaluates
  Organic (nirio's armed read today: Organic, original installed_at
  intact — the Sep-8 Kwanko booking was overwritten at some ask since).
  Discipline: on a consented capture row, the ARMED READ is the first
  thing to do — every signed ask re-evaluates the row.
- **Cold-ask signature-second throttle**: an attribution GET whose
  signature carries an ANCIENT signing second (genuine capture sig)
  answers 400 `{adid, ask_in}`; a fresh-signed ask answers 200. The
  server derives ask time from the (validated) MINSTD header second —
  explains prior G=400 vs ours=200 splits on nirio/eatr/watsons.
- The no-consent state's NAME is per-app config (same-minute control:
  PENTI → "No User Consent", hunch → "Organic"), but the STORED STATE
  (deeplink, engagement_time) persists regardless.

- On a **direct `app.adjust.com` link** the device-match param is `idfa=`
  (iOS). `sub3=` is only a publisher macro — it does NOT device-match
  (proven on hunch 1yzhva5b: sub3-only click never joined; sub3 only
  works when a partner tracker forwards it INTO the link as `idfa=`,
  as appsatiate did for adj8ios).
- A click that will book echoes `click_id=` (+ the matched idfa) in the
  302 Location. A bare store redirect (no click_id) = the click is not
  being matched — no funnel shape fixes that from the same IP
  (sdk_click with/without, CTIT 8 s vs 20 s, att0/att3 all Organic).
  That wall is server-side click acceptance (nirio hit it too): needs a
  mobile-carrier IP shared by click+session, or a real device click.
- A RANDOM `attribution_token` in a fresh-row `source=apple_ads`
  sdk_click is **accepted (200)** by analytics.adjust.com — it does not
  error like an aged genuine token (nirio's 500), but books nothing.

## adj7ios quick law (details in adj7ios/README.md)


blob(304) = MINSTD-header(16) ‖ AES-256-CBC body(256, key SEED, IV
header, no-final-SubBytes SPN) ‖ HMAC-SHA256(DK37) tag(32); record =
JSON `{a,b,c,d,e}` with cert40 = ASCII "0"×40; claims = 98-key pool,
`1300000` pinned before `seq`, block2 (activity_kind, client_sdk) last.
activity_kind: session/click/attribution/**info**(sdk_info)/**event**/
third_party_sharing. headers_id/native_version per SDK build ride in the
auth header only (ios5.4.6→7/3.61.0, ios5.5.0→8/3.62.0). Charles `.chls`
carving: strip `<endpoint>?` prefix from query chunks; ASCII-only URL
class; framing keys after `q\x00~` must not join the last value.
