# iOS adj9 verification — status after full multi-agent run (2026-10-01, rev 2)

Source capture: `Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz`
Cainiao (com.cainiao.cnintl4iphone), 30 signed requests (2 sdk_click, 1 session,
26 event, 1 attribution), `Client-Sdk: ios5.8.0`, iPhone13,2 / iOS 26.5.
Note: the capture is an **`ios-simulator` build** (`{"os_name":"ios-simulator"}`),
produced by an external simulator service — no iOS binary exists on this machine.

Detailed stage reports: `_sub_ios_header_RESULT.md`, `_sub_unseal_RESULT.md`,
`_sub_android_event_RESULT.md`, `_sub_ios_mint_RESULT.md` (in `one_click_run/`).

---

## VERDICT

**The algorithm is shared with Android end-to-end, except two platform-specific
pieces — one solved (the header PRNG), one isolated (the claims payload).**

| layer | shared? | proof |
|---|---|---|
| envelope 192 B = 16 header + 176 body | YES | 30/30 |
| `algorithm="adj9"`, ids 1500000/10/5.0.0 | YES | 30/30 |
| body cipher (14-round SPN, CBC from header) | YES | `whiten_inverse` unseals 30/30; **binary-level: iOS core carries the same KB (XOR-0x55, 481-site unrolled block), IV2 (XOR-0xCCCC) and digest-key dwords (plain)** |
| digest MAC (double-padded SHA-256, secret K) | YES | 30/30 verify |
| record layout + constants | YES | magic `01 00 08`, `SHA256("")` @79..110, `0e`×14 tail — 30/30 |
| region materializer (d0 from seed S) | YES | `region(S)` reproduces the d0 head 30/30 |
| BLOCK recipe (`sha256_iv2(D9‖00 08‖head16‖LE32(S)‖SHA256("")‖variant‖dev‖claims)`) | YES | Android-proven 354/354 |
| header LAW (shape: 8 draws → 4 XOR pairs → BE32) | YES | same composition as Android |
| **header PRNG** | **iOS-specific — SOLVED** | see §1 |
| **claims PAYLOAD** | **iOS gap — see §4** | ~93M corrected hypotheses exhausted |

### iOS-only record deviations (3, inside the shared container)

| field | iOS | Android |
|---|---|---|
| byte 112 | `0x02` | `0x01` |
| D9 (cert slot, 25..44) | **20 zero bytes** — no APK cert concept | APK cert SHA-1 |
| 16-B field @114..129 | `"iPhone13,2"` zero-padded | 16 zero bytes |

Region selector phase: iOS `(0x40,)` (pure cycle) vs Android `(0x2B,0x48)`.

---

## 1. Header — SOLVED (28/28 + uniqueness)

```
seed = time(NULL)                      # same-second requests share the header
x    = seed mod (2^31 - 1);  if x == 0: x = 1
D[k] = 16807 * D[k-1] mod (2^31 - 1)   # k = 1..8  (Park-Miller / MINSTD)
w_i  = D[2i] ^ D[2i+1]                 # i = 0..3  (post-step draws, NOT d[0]=x)
header = BE32(w_0) || BE32(w_1) || BE32(w_2) || BE32(w_3)
```

- Verified 28/28 distinct headers; signing seconds recovered by inversion,
  unique per second; ±1-day injectivity scan (177k s): zero collisions.
- The only degenerate seed pairs sit at epoch 0 / 2038 wrap — never in practice.
- Offset vs request second: 21×0, 3×+1, 2×−1, 1×−2, 1×−9 (the −9 is the
  install-time sdk_click, signed early and queued).
- **Only the generator differs from Android** (bionic TYPE_3 additive feedback vs
  MINSTD Lehmer); composition identical. `adj9_signer.make_header` reproduces
  none of the iOS headers and all 9 Android golds — the laws coexist cleanly.
- Implementation trap: pairing must use the 8 **post-step** draws D1..D8.
  "d[0] = x" readings give 0/28.
- Why earlier Apple tests failed: FreeBSD/Apple `do_rand` wraps every call in
  `x = (ctx mod (2^31−2)) + 1` (a per-call +1 recurrence) and `srand(0)→123459876`;
  the iOS lib uses the raw Lehmer step with no wrappers.

## 2. `adj_verification` — SOLVED

```
adj_verification = BASE64( cycle19("Quoh8uafohgh7CahM2h") XOR {"os_name":"<os>"} )
```

- Key is **19 bytes, cycled** (the earlier "21-byte key" reading was key + 2 bytes
  of its own repeat; only the 27-B ios-simulator value disambiguates).
- Verified: android → `KlcAG2cbAAsKSl1KVi0FGiJbDHMI`;
  ios-simulator → `KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb` (this capture);
  **real device `{"os_name":"ios"}` → `KlcAG2cbAAsKSl1KXiwSSjA=`** — do not reuse
  the simulator constant on hardware.
- All 30 captured values decode to `{"os_name":"ios-simulator"}`.

## 3. `/event` claims law — proven (Android 91/91 + 27/27 byte-exact mints)

Derived from 193 genuine penti on-device frida signings (27 events) and the
block oracle (91/91); mirrors to iOS keys:

```
sorted(PROFILE + [event_count, event_token, partner_params])   # partner_params→callback_params on iOS
  → pinned adj_signing_id (1500000)
  → sorted(SESSION_TAIL + [seq])
  → [activity_kind, client_sdk, headers_id, native_version]
bare latin-1 values concatenated, no separators; JSON values raw
```

Placement is load-bearing: event keys BEFORE the pinned id, `seq` AFTER it
(both alternative placements fail 27/27).

## 4. The one open item — iOS claims payload

Every record byte except the 32-B BLOCK matches the capture byte-exactly; the
divergence starts precisely at rec[46]. `mint_ios(claims=...)` reproduces the
blob the moment the claims string is known.

Exhausted (`_sub_ios_mint_RESULT.md` has the full inventory, ~15M hypotheses):
Android-law over iOS bodies (incl. the 11-key session law), iOS-name and
canonical-name laws, 12–15-key toggle subsets × tail subsets × pinned/BLOCK2
variants, wire-order, k=v serializations, length-prefixed/dword-padded claims,
~800 BLOCK frames (D9 zeros/empty, byte-order variants, S-slot encodings,
15+ tails, slot permutations, self-referential candidates).

**Final state after ~93M total hypotheses across three search generations, ending
with a corrected oracle: 0 BLOCK matches.** Agent V's stage also **found and fixed
two harness defects that had been silently invalidating earlier negatives**:
(1) `oracle_batch` zero-filled mixed-length batches, digesting extra all-zero
blocks after short claims' length fields — provably wrong digests; fixed with
length-grouped batching (`_sub_claims3_oracle_fixed.py`, 9/9 golds + positive
controls; **all future BLOCK searches must use it**); (2) a regex capture bug let
a trailing `\r` into every `authorization` header value. The prior stage-B space
(10.5M membership masks) was re-run exactly on the fixed oracle — still zero.

What the corrected search covered: the full decoded core vocabulary
(`network_payload`, `authorization`±signature, `signature`, `secret_id`,
`environment`, `os_name`, `algorithm`, `adj_verification`, `endpoint`) × the
Android law / binary hint order / dict order / auth-header order / wire order /
vocab-only × 24 envelope permutations × membership subsets to 2^18 per kind ×
k=v/length-prefixed/JSON serializations × timestamp forms × 30 BLOCK frames.

**Ranked remaining hypotheses (local search exhausted):**
1. **App-Store-receipt-derived claim bytes** — the core provably parses the
   receipt in-binary (PKCS#7 OIDs embedded); receipt bytes never touch the
   wire, so they are unrecoverable from any capture. Structural consequence:
   the server never sees them either ⇒ it cannot re-verify the BLOCK, only
   check consistency — the same model as the Android TEE analysis. One live
   mint would test it.
2. `secret_id` as a per-app constant baked into the closed core (invisible to
   the decoded string pool).
3. An exotic serialization family (low residual).

Two consequences:

1. **If the core injects nonce/receipt-derived claim bytes, the server cannot
   re-derive them either** — the same structural argument as the Android TEE
   analysis (server checks consistency, not recomputation). Fresh-mints with
   fabricated claims should then pass the same checks. Proving that means
   sending to production, which is the user's call, not something to run
   unilaterally.
2. **The definitive settle is one instrumented ios-simulator signing**: frida on
   `ADJSigner sign:withExtraParams:withOutputParams:` — the same method that
   settled Android. `mint_ios(claims=...)` then reproduces captures
   byte-exactly.

Remaining local avenue: the core binaries are public (`adjust/adjust_signature_sdk`
v5.0.0 releases ship the iOS xcframework and Android AAR). Cross-diffing the iOS
arm64 slice against the Android core — whose behavior is fully known — can
locate the shared constants (IV2/KB/K), the claims key strings, and the iOS-only
injection sites (`_sub_core_*` analysis).

## 5. Scoreboard

| check | score |
|---|---|
| Android golds through the shared iOS pipeline | 9/9 byte-exact |
| iOS headers (MINSTD law) | 30/30 |
| iOS digest MAC | 30/30 |
| iOS d0 head via region(S) | 30/30 |
| iOS non-claims record fields | 30/30 |
| iOS full-blob re-mint | 0/30 — claims bytes pending (48–50/192 bytes match) |

### Claims-input classification (from `_sub_ios_claims_law_RESULT.md`)

| class | fields |
|---|---|
| per-install — generate fresh (SUCCESS class) | idfv, idfa, dedupe tokens, all timestamps, all counters (session_count, event_count, seq, session_length, time_spent, enqueue/retry/queue_size), att_status, attribution_token, fb_anon_id, callback_params, SKAN state |
| constants | app_token, bundle_id, versions, device fields, environment + the whole auth envelope |
| mystery | only the BLOCK's 32 claims bytes (closed-core injection) |
