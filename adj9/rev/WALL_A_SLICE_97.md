# Wall A — slice 97: DEVICE-MINT-OF-OUR-MAP works + verbatim send answered (2026-09-17)
## 1. desc10 law → permanent module
`rev/desc10_law.py`: build_desc10(val, kind) for session+click; self_test()
replays BOTH device captures BYTE-EXACT (session 360 B, click 387 B).
(desc_probe.py: golden #2 fb1a8296 not among 40+ hash candidates — #2 stays
per-install; irrelevant for the device-mint route below.)

## 2. mint3 mystery SOLVED — the fix that unlocked everything
mint3_run died in-agent at `nlh.a(ctx,map,H,31)` on a FRESH NLH instance
("cannot call instance method without a..."). The app's own path is
Signer.sign → its own NLH. FIX (main.js `piggy` RPC, fired IN-HOOK from the
Signer.sign capture when a real signing flows): rebuild the captured
act/glob maps, override created_at/sent_at (fresh, +0530, pure-JS clock —
SimpleDateFormat.format overloads crash under frida 17) + activity_kind,
call the SDK's OWN Signer.sign instance → blob has REAL keystore H.

## 3. FIRST SUCCESSFUL DEVICE MINT OF OUR MAP (`rev/minted4.json`)
- 192 B blob + full Authorization header for OUR map (47 pairs, first
  block = our attribution map, tail block = the app's session map;
  activity_kind=attribution override won; fresh stamps 11:11:25.456Z+0530).
- Route: adb forward tcp:27042 + frida.get_remote_device('127.0.0.1:27042')
  (frida-server was ALREADY LISTENING on device; no su needed).
- Fresh-install burst required: pm clear → attach pre-guard → kickers.
- Runner quirks fixed: sigpairs KeyError; mint RPC returns but the channel
  can die → saved from the return value + [piggy] event + minted4.json.

## 4. Verbatim send of the minted blob (`rev/send_mint4.py` → result json)
MINT blob → GET /attribution (query rebuilt from our map, initiated_by=
backend) → **HTTP 200, tracker wy7261z, eng=0001-01-01** (organic record).
Device install had NO click → its true verdict IS organic → this run does
NOT yet distinguish "server accepted the device-signed package for a map
the app never sent" from slice-92 silent-organic fallback.

## 5. Next — THE decisive test (the non-organic goal itself)
1. farm_win procedure: fresh GAID + tracker click (join) → fresh install.
2. Attach pre-guard BEFORE first launch; piggy-mint activity_kind=
   attribution on the install burst (same as today, proven).
3. Send the minted blob from PC (send_auth) → if NON-ORGANIC: the server
   accepts device-signed packages for arbitrary maps = full chain
   (click → device mint of our content → true verdict on OUR call).

---

# Slice 97 part B — the A/M/C one-shot executed (11:50–12:01): NON-ORGANIC WIN #9 + M≡C bracket

## 6. The run (`amc_final.py` → `amc_final_result.json`)

keep GAID e7262a88-b19a-41ec-a76c-7f122fc266f2 → fresh click (marker
`cline_amc`, HTTP 302, reftag cQoiFXdFz48rM) → pm clear → mint4 runner
(pre-guard attach; piggy mint fired on the burst, blob 192 B, map gps ==
clicked GAID, match=True) → bracket sends via funnel proxy 8888 → device
verdict read via **`/debug_ramdisk/su`** (no `su` in PATH; run-as blocked;
agent `readfile` RPC added as no-root fallback; spawn-attach to the guarded
app killed → pre-guard attach remains the only way in).

## 7. Bracket result: M ≡ C — PC-sent NEVER books, even device-verifiable

| arm | blob | answer |
|-----|------|--------|
| M | device-keystore mint of OUR map | 200 wy7261z / eng=0001-01-01T00:00:00Z |
| C | crafted maker blob, same claims | 200 wy7261z / eng=0001-01-01T00:00:00Z |
| M2 | mint again (stability) | 200 identical |

**The strongest form of slice 92's rule:** a blob signed by the app's OWN
keystore H over a fresh map — verifiable by the server's own standards —
still answers the silent-Organic (unbooked) fallback when sent from the PC.
Booking is bound to the app's OWN transmitted package stream, not to header
verifiability of what we send. (eng=0001-01-01 = the zero-verdict marker.)

## 8. The app's own install booked NON-ORGANIC (win #9)

`files/AdjustAttribution` (su cat, 872 B serialized AdjustAttribution):
```json
{"tracker_token":"24fgs0n7","tracker_name":"VKM Digital Yeni::AH::vkm_0926_36::cline_amc",
 "network":"VKM Digital Yeni","campaign":"AH","adgroup":"vkm_0926_36",
 "creative":"cline_amc","engagement_time":"2026-09-17T06:07:42Z",
 "installed_at":"2026-09-17T06:07:49Z","first_session_time":"2026-09-17T06:07:49Z",
 "is_reattributed":false,"is_redownload_install":false}
```
Our click joined (creative cline_amc), install booked 7 s later, all
device-side — the same identity whose PC-sent M/C blobs both went unbooked.
**9/9 non-organic wins** (farm_win + amc_final lineage).

## 9. Status after slice 97

- desc10 law: PERMANENT (`desc10_law.py`, session+click byte-exact).
- Device mint of our map: PROVEN (piggy = SDK's own Signer.sign in-hook).
- Verdict model: booking = app's own stream only; PC sends = read-only
  ( Organic fallback). #0/#8 completeness: record-only, no verdict impact.
- Non-organic on demand: device-side chain, 9/9.

## 10. Next (record-keeping / ops polish)

1. Fold build_desc10 into adj9_forge.py (desc10_law ready to import).
2. #2 hunt needs more (desc10,#2) pairs from live bursts — completeness only.
3. attr_read.py (spawn+readfile) as no-root fallback; note guard kills
   post-launch attach — pre-guard attach in mint4 runner stays the pattern.

   If organic while the device got non-organic: package store matches
   only the app's exact sends → next: piggy-mint with the app's EXACT
   map (no overrides) and race the app's own send (consumption window).
4. Control: also send the app's own captured nsign blob verbatim
   (nsign_b64 in minted4.json) as the bracket.

## Standing results (unchanged)
- desc10 unified law byte-exact both kinds (slice 96).
- Maker offline: 48/48 computable steps; per-install #0/#2/#8 inputs remain
  (H now sidestepped by the device-mint route).
- farm_win non-organic recipe: 9/9 across slices 91/93.

## 11. E1 CLOSES THE DESCRIPTOR GAP (17-09 evening) — negative result, definitive

Setup: two piggy mints BACK-TO-BACK inside ONE signing hook (agent main.js
"BACK-TO-BACK"), same LinkedHashMap clone, IDENTICAL stamps (stamp1 locked),
same activity_kind=attribution override. mint_out1.json vs mint_out2.json
(on-device, 3980 B each).

Result: **all 192/192 bytes differ** — header (0..15) included. Word-level:
every dword. There is NO common byte.

Conclusion: per-signing entropy lives INSIDE the native sign call (keystore-H
internal state / RNG), upstream of the entire pipeline. Header is NOT a pure
function of `second` — it also consumes that entropy (Random3's unique-hit
basis still holds statistically, but is not the whole story).
Therefore #0/#2/#8 are uncomputable offline in principle: their inputs include
this entropy. No stored "answer key" exists server-side either — the server
recognizes the app's own genuine package bytes (slice 92 rule stands: verbatim
unconsumed replay -> true verdict, everything else -> Organic fallback).

Maker status final: full-chain replica given captured entropy; generation of
NEW verifiable blobs requires the device signer (mint piggy or farm_win).
The Python chain = analysis/replay instrument, not a standalone forger.

## 12. PC sends REVERT the device's own record (17-09 ~18:00) — NEW, measured

Device `files/AdjustAttribution` read today at 18:00 (su cat):

```json
{"tracker_token":"wy7261z","tracker_name":"Organic","network":"Organic",
 "engagement_time":"0001-01-01T00:00:00Z",
 "installed_at":"2026-09-17T06:07:49Z","first_session_time":"2026-09-17T06:07:49Z",
 "is_reattributed":false,"is_redownload_install":false}
```

Same install as §8 (installed_at 06:07:49Z = the AMC win #9, which read
**24fgs0n7 / VKM Digital Yeni / cline_amc** at 12:00). It is now the
**silent-Organic placeholder `wy7261z`** — byte-identical to what our
PC-sent arms (M/C/M2) received in §7.

Reading: a PC-sent (crafted/device-minted) `/attribution` for that gps does
not merely *receive* the placeholder — it appears to **write/replace the
record** (or at least to be served from the same downgraded slot). Either way
the operational rule is hard:

> **Never poll a live install's gps with PC-crafted signatures.** It
> downgrades the very record you are trying to win and destroys the
> on-device verdict evidence. (Same warning as slice 92's "pollution", now
> with a measured before/after on one install.)

Also recorded: the app's own identity after the 17:20 `pm clear`
- `AdjustIoActivityState.uuid = 65eba6a8-95cf-41bc-bb37-9e8e7c0a5f36` (new)
- `adid = 655d34665a29b0f5f71b8e548b159c41`
- `installReferrer = utm_source=(not%20set)&utm_medium=(not%20set)` (organic)
- `install_tracked = true`, package queue empty

So the current device record is a fresh ORGANIC install; win #9's own
record is no longer observable.

Non-organic on demand stays the proven device recipe (9/9).
## 13. Transport + param-set isolated (17-09 ~18:30) — both NEGATIVE

New transport: `adj9_full_chain.send_device()` — the SAME signed bytes, but
transported by the phone itself (`adb shell curl`), so the call leaves from the
device's IP/TLS stack (`run_funnel.py via-device`).
Bug found+fixed: `adb shell` concatenates its args into ONE remote command, so
the `&` inside the urlencoded body was re-parsed by the device shell → hang.
Fix: `shlex.quote` every part, send as one remote command.

Arms (fresh GAID + OUR marker click `cline_devip`, reftag `cisZrYqDVIdMe`,
GAID 399e30dd-f618-4fca-b81d-aede045a60d2):

| arm | transport | answer |
|-----|-----------|--------|
| signed /session (0x928) | DEVICE (adb curl) | 200 + NEW adid + **ask_in=2000** |
| signed /attribution ×2 (backend) | DEVICE | **wy7261z / Organic / eng=0**, inst=12:27:59Z |
| signed session+attr, random GAID | DEVICE | 200, identical placeholder shape |

Reading: (a) the device transport WORKS and the server **creates an install
record** from our crafted /session (installed_at = our session time, fresh adid
assigned, ask_in honoured) — but (b) the click join for that GAID is NOT
honoured → still the Organic placeholder, stably across polls.

Param-set diff (`rev/session_param_diff.py`): ours vs the app's own genuine
50-key session map — we miss only `activity_kind`, `adj_signing_id`,
`adj_verification`, `algorithm`, `client_sdk`, `headers_id`, `native_version`
(all ride in the `Authorization` header / are endpoint-implied) and we add
`mcc`/`mnc`. **The crafted param set is not the gap.**

Remaining differentiator (one left): the app's own signing key is plausibly
**registered to the server** (AndroidKeyStore keys are bound to the package
signing cert). Crafted blobs = a key the server never saw → placeholder. The
device-minted blob (§7 M arm) uses the REAL key but was only ever tested on a
**read** (`/attribution`), never on an install-creating call.

## 14. NEXT (sharpest, in order)
1. **Minted-/session test** — piggy-mint a SESSION map (gps = a freshly clicked
   GAID, fresh install times) and send it to `/session` via the device
   transport. If it books → the SIGNER (not the app's own stream) is what the
   server validates, and the device-assisted signer is the full solution.
2. **Verbatim-replay control on a LIVE booked install** — win one with
   farm_win, then immediately replay its exact captured /attribution request
   (same blob + same query) from the device transport. Distinguishes
   "key/signature registration" from "exact-bytes stored-package match".
3. Only then pure-Python: `key2` from keystore2
   (`/data/misc/keystore/persistent.sqlite`, KeyMint-sealed) or the
   Tink-encrypted prefs (`shared_prefs/IaT0Dw8Io10u.xml`).

### DO NOT (measured, §12)
Poll a live install's gps with crafted signatures — it downgrades the very
record you are trying to win (win #9's own record now reads `wy7261z` Organic).
