# adj7ios — the Adjust **adj7** signature on **iOS**

Standalone port of the adj7 law to iOS, **re-verified from scratch** on two
independent captures (prior work distrusted, nothing reused but the
recorded constants, which the fresh blobs re-prove):

| capture | app | SDK | native | headers_id | signed reqs |
|---|---|---|---|---|---|
| `ct_Watson_logs_18Aug_ios.saz` (Fiddler) | com.alfuttaim.watsons.uae | react-native5.5.0@ios5.5.0 | **3.62.0** | **8** | 4 (sdk_click, session, sdk_info, attribution) |
| `hunchdatingiosauto_newapp_1appril2026 (1).saz` (Fiddler) | hunch dating | **flutter5.5.0@ios5.5.0** | **3.62.0** | **8** | 4 (sdk_click, session, attribution ×2) — armed re-read 2026-10-08: Organic on the 2026-10-02 epoch (device reinstalled; April state replaced), O == G == ARM |
| `eatr_lvl2_install1_15may_iosprs.saz` (Fiddler) | com.eatr.eatr | react-native5.4.4@ios5.4.6 | **3.61.0** | **7** | 4 (session, sdk_click, attribution, sdk_info) — **armed replay reproduced the logged verdict verbatim, engagement 2026-05-15 stored 146 days later** (the permanence proof) |
| `lululemon_newapp_13may_ios11.chls` (Charles) | com.rettersoft.lululemon | react-native5.5.0@ios5.5.0 | **3.62.0** | **8** | 4 (sdk_click, session, **event**, attribution — booked admatic) |
| `nirioiosauto_08Sep_ios_CT.saz` (Fiddler) | com.fdjservices.nirio | react-native5.4.4@ios5.4.6 | **3.61.0** | **7** | 6 (tps ×3, sdk_click, session, attribution) |

```
python make_gold.py            # carve both captures -> gold_vectors.json (10 vectors)
python adj7ios_pure.py         # selftest: 10/10 byte-exact + tag/decrypt/record/H re-verified
python run_verify.py <file.saz># per-layer verify any adj7-iOS capture
python replay_attr_test.py     # the attribution replay rule (live)
```

## The law

```
blob(304) = header(16) || body(256) || tag(32)

header    raw MINSTD: x = signing second mod 2^31-1 (0 -> 1); 8 draws
          x = 16807*x mod p; w_i = d[2i]^d[2i+1], big-endian     (16 B)
          (Android adj7 uses the bionic 31-word LCG + 310-draw warm-up)
body      CBC-AES-256 over the record; key = SEED, IV = header;
          the measured ShiftRows SPN, NO final SubBytes          (256 B)
record    '{ "a":  <A> ,"b": "<H>","c": "<cert40>","d": "<D8>",
            "e": "<sha256('') hex-upper>" }\x00' + 0x10*16
          A = str(u64le(nonce12[:8])) rjust 20; D8 = hex-upper(nonce12[8:12])
cert40    ASCII "0"*40 — the iOS no-cert path (Android: NUL bytes)
H         sha256 with custom IV0 over cert40 || nonce12 || SHA0_HEX || claims
claims    the 98-key pool order, present values bare-concatenated,
          adj_signing_id "1300000" pinned before "seq",
          block2 (activity_kind, client_sdk) appended last
tag       HMAC-SHA256(DK37, body)                              (32 B)

auth      Signature signature="<608 hex UPPER>",adj_signing_id="1300000",
          algorithm="adj7",headers_id="7|8",native_version="3.61.0|3.62.0"
```

`headers_id`/`native_version` are per SDK build (ios5.4.6 → 7/3.61.0,
ios5.5.0 → 8/3.62.0) and ride in the auth header only — the blob itself is
identical law across both builds.

### activity_kind per endpoint (each confirmed byte-exact)

| endpoint | activity_kind |
|---|---|
| `/session` | `session` |
| `/sdk_click` | `click` |
| `/attribution` | `attribution` |
| `/sdk_info` | **`info`** (not `sdk_info` — same as adj8-iOS) |
| `/third_party_sharing` | `third_party_sharing` |

## Verification record (2026-10-08, distrust mode)

Every layer re-derived from the raw `.saz` bytes — no frozen vector, no
prior artifact consulted (`watsons_verify.py` in `../adj7/ios` holds the
audit copy of this run; `make_gold.py` re-derives everything on demand):

| layer | watsons (4 blobs) | nirio (6 blobs) |
|---|---|---|
| L0 structure 304 B | 4/4 | 6/6 |
| L1 tag HMAC(DK37) | 4/4 | 6/6 |
| L2 record decrypt (SEED), cert40 ascii-0, 0x10 pad | 4/4 | 6/6 |
| L3 MINSTD header, **unique** second in [sent_at−120, wire+30] | 4/4 | 4/4 distinct seconds, 2 shared (sids 32/33 same second, as on-device) |
| L4 claims/IV0 law (+ sdk_info kind probe → `info`) | 4/4 | 6/6 |
| L5 **byte-exact mint** | **4/4** | **6/6** |

Signing-second behaviour matches the device story: the Watsons sdk_click +
session were signed in the **same second** (1787030534 = the sent_at
second) and share the 16-B header; sdk_info/attribution follow at +9/+11 s;
every second found is unique in a ±150 s window and ≤ wire time.

## Attribution replay rule — PASSED (live, 2026-10-08)

Logged verdict (Watsons sid 110, 18 Aug): HTTP 200, adid
`ca7afe2af868639f9e8d06be7441137b`, `tracker_token "unattr"`,
`tracker_name`/`network "No User Consent"`, `engagement_time 0001-01-01`,
`installed_at = first_session_time = 2026-08-18T05:22:22Z`.

| probe | result |
|---|---|
| **G** genuine verbatim (the phone's exact bytes today) | HTTP 400 `{adid ca7afe2a…, ask_in 7200000}` — the row's ask-cadence throttle |
| **O** ours, capture map, fresh second+nonce | HTTP 400 `{adid ca7afe2a…, ask_in 7200000}` — **identical to genuine** |
| shape variants (`initiated_by=all`/absent, unsigned) | identical 400+adid+ask_in → the throttle is row state, signature-independent |
| **ARM** our signed `/session` → wait `ask_in` → our signed `/attribution` | session **200** `{adid ca7afe2a…, ask_in 5000}` → attribution **200** with the **exact logged object**: `unattr / No User Consent`, engagement `0001-01-01T00:00:00Z`, `installed_at 2026-08-18T05:22:22Z` — **every field identical to the genuine device's answer** |

So our mint is accepted through the exact device flow and reproduces the
logged verdict verbatim — the user rule satisfied literally. (A 400
`{adid, ask_in}` on the raw GET is the throttle the genuine signature also
receives; the SDK never asks cold, it arms via the session's `ask_in` —
which is what ARM does.)

### The adj9-shape controlled experiment (2026-10-08, the "same response" question)

The user's standard: the replay must return the logged response, as adj9-ios
proved.  Controlled test, same minute, same machine — the exact adj9
fresh-install shape (att0 + `tracking_enabled=0`, no idfa, curl_cffi
safari17_0, session → 8 s → `initiated_by=backend` attribution, no click):

| app | signer | answer |
|---|---|---|
| PENTI (`adj9_fresh_install.py`, unchanged) | adj9 | **`unattr / No User Consent`** — the adj9 proof reproduced on the day |
| hunch (`hunch_fresh_noconsent.py`, same shape) | adj7ios | `yuzxv6m / Organic` |

The adj9 proof is reproducible today; the identical shape through the adj7ios
mint gets hunch's current answer.  The no-consent state's **name is per-app
server config** — PENTI names it "No User Consent", hunch names it "Organic"
today (its own April capture logged "No User Consent", so the app's naming
and/or row state drifted since — its automation device also re-ran Oct 2).
Same-as-logs through our signature holds exactly when the app's row + naming
still match capture day: **PENTI and watsons both reproduced byte-exact**;
for drifted apps no signature — the genuine one included (G control) — can
fetch the old wording back.  (Side fix: `adj9_ios/adj9_claims_law.py` pointed
at a moved `adj7_work/adj7s4_pool_order.json`; patched to the local
`adj9_pool_order.json`, after which the script reproduced its verdict.)

### Enforcement observations (same day)

- `/session` on **fresh rows**: ours / tampered-tag / unsigned all answer
  200 + adid — analytics.adjust.com does not hard-reject a broken adj7
  signature at the session layer (same soft-enforcement as the consent
  host on nirio; Adjust uses the signature downstream as a fraud signal).
- The byte-exact offline mint (14/14) plus ARM == logged verdict is the
  correctness proof; endpoint hard-enforcement is not required for it.

## eatr — the permanence proof (2026-10-08, user's rule vindicated)

`eatr_lvl2_install1_15may_iosprs.saz` (com.eatr.eatr, analytics host,
react-native5.4.4@ios5.4.6, headers_id 7 / native 3.61.0): **4/4
byte-exact** — fifth app; 22 frozen vectors, selftest 22/22.

Its logged attribution was the hybrid state: `unattr / No User Consent`
**with a fully engaged click trail** (deeplink `adj_t=20sh9rpe`, campaign
Traffy_Optifuze_ios, adgroup Optifuze, `adj_click_id`,
`adj_idfa=0C3B1577…`, appsatiate install+event callbacks,
`engagement_time 2026-05-15T05:26:24Z`, install 05:28:37Z).

Replay, 146 days later, row untouched by us (G first):

| probe | result |
|---|---|
| G genuine verbatim (cold) | 400 `{adid 04011085…, ask_in 7200000}` — ask throttle, row resolved |
| O ours (cold) | identical 400 — signature layer PASS |
| ARM our session → `ask_in:5000` → our attribution | **200 — LOGGED VERDICT REPRODUCED**: `unattr / No User Consent`, **engage `2026-05-15T05:26:24Z` still stored**, installed `2026-05-15T05:28:37Z`, same adid |

**The permanence law (corrects the earlier "aging" framing):** a
consent-GATED row (att0/att2, No-Consent) never re-evaluates — its stored
attribution state, including the engaged click trail, is permanent in
Adjust's DB, so same-as-logs through our signature is always achievable
(proven now on watsons, eatr, PENTI). A **consented** row (att3 —
lululemon, nirio) re-evaluates on every ask, so its booking expires with
the attribution window; and a **reinstalled** row (hunch, Oct 2) starts a
new epoch. Those are the only two cases where logs ≠ today — neither is a
signature matter (the G controls behave identically).

## lululemon — third app, the event kind, and an aged-booking replay
(2026-10-08)


`lululemon_newapp_13may_ios11.chls` (Charles, consent.adjust.com,
com.rettersoft.lululemon, ios5.5.0 build): **4/4 byte-exact**, which adds
the first `/event` vector to the frozen set (kind = `event`, confirmed
byte-exact — the kind adj8-ios could not close). Total: **14/14 vectors,
6 request kinds, 3 apps, 2 SDK builds.**

Replay (`replay_lululemon.py`): the logged verdict was a **booked
non-organic** (tracker `20ql0xil`, network admatic, campaign admatic_2,
engagement 2026-05-13T04:54:59Z, adid `9d755291bd3d4180be3e7c0c9fe4c160`)
— 148 days old at replay time:

| probe | result |
|---|---|
| G genuine verbatim | 200, same adid, **Organic / 1vpot25n** — the booking aged out; the genuine signature itself gets Organic today |
| O ours fresh sig | **identical to G on every field** (tracker, network, engagement 0001-01-01, installed_at) — signature layer PASS |
| ARM our session → ask_in 2000 → our attribution | 200, same adid, Organic (row re-evaluated, installed_at refreshed) |

This is the aged-booking pattern established on nirio and adj7-Android:
a **consented** row answers live re-evaluation — after the attribution
window the evaluation is Organic for anyone.  (Nirio re-checked with an
armed read on 2026-10-08: Organic, original installed_at intact — the
Sep-8 Kwanko booking was overwritten by a later ask; consented rows are
re-evaluated by every signed ask, so the armed read should always come
first on such rows.)  The standing rule for reading these replays is
codified in the workspace `AGENTS.md`.

**Correction (post-run audit):** the first G probe was not byte-verbatim —
the carved query chunk carries the URL path prefix
(`attribution?bundle_id=…`), which the replay concatenated after its own
`/attribution?`, so the request went out with `?attribution?bundle_id=`
as the first (junk) param and **no valid `bundle_id`**. The row still
resolved (app_token + idfv), and the verdict was unchanged — but G was
re-run after the fix (exact wire query, `bundle_id` present, plus an
`initiated_by=all` variant): still `200 Organic / 1vpot25n`, identical to
ours. The ARM session rate-limit (`400 request check interval failed`)
on the re-run is the documented 20-min per-adid session cadence — our
first ARM session (200, `ask_in:2000`) already proved acceptance, and it
re-stamped the row's `installed_at` to the replay day, which is why the
later probes show `installed=2026-10-08` while the very first G (before
any of our sessions) showed the row's original `2026-05-13T05:15:48Z`.

Charles `.chls` carving notes (encoded in `verify_chls.py`): a GET query
chunk can swallow the URL path (`attribution?bundle_id=` — strip the
`<endpoint>?` prefix), the URL class must be ASCII-only, and framing keys
after `q\x00~` must not join the last value.


## Files

| file | what |
|---|---|
| `adj7ios_pure.py` | **the signer** — self-contained (constants + crypto + iOS deltas); `selftest()` mints all gold vectors byte-exact |
| `make_gold.py` | carve both captures, derive (second, nonce12, kind) per blob, assert byte-exact, freeze `gold_vectors.json` |
| `run_verify.py` | `python run_verify.py <file.saz>` — the per-layer table on any new capture |
| `verify_chls.py` | `python verify_chls.py <file.chls>` — the same for Charles captures |
| `replay_attr_test.py` | the watsons replay-rule proof (G/O/ARM + optional `--fresh-row` enforcement triad) |
| `replay_lululemon.py` | the lululemon aged-booking replay (G/O/ARM vs the logged admatic verdict) |
| `gold_vectors.json` | the 14 frozen genuine vectors (params, kind, second, nonce12, sig) |
| `lululemon_carved.json`, `replay_attr_result.json`, `replay_lululemon_result.json` | carve + raw replay bodies |

Captures are not kept here: both live in `C:\Users\Apps\Downloads`
(`ct_Watson_logs_18Aug_ios.saz`, `nirioiosauto_08Sep_ios_CT.saz`;
`*.saz` git-ignored).

## Relation to the other folders

- `adj7/` (Android): same blob/record/claims/tag; deltas = header PRNG
  (bionic LCG), cert40 (NUL bytes), per-app cert SHA-1 on real devices.
- `adj8ios/`: next generation — 176-B blob, AES key/IV2/DK38 set, fixed
  `headers_id="9"`, `adj_signing_id="1400000"`; adj7's 304-B JSON-record
  shape with the 98-key pool is the older law kept here.
- The prior crack notes for nirio live in `../adj7/ios/` (README,
  REPLAY_RESULT) — this folder supersedes them with the standalone,
  two-capture-verified signer.
