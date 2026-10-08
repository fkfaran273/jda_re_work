# EVENT + BURGER AUDIT — final (2026-10-07)

Data: `D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin`
(237,464 B, 145 requests, Content-Length framing consumed **exactly** — no
stream gaps, no truncation). Work dir: `work\eb_audit\`.

## 0. Executive summary

1. **The dump contains NO burger event.** The 11-request tail alignment in
   the task brief is off by one. Actual tail:
   `130 h_event(15:39) · 131-133 h_sess/h_click/h_attr · 134 h_event(15:47)
   · 135-137 h_sess/h_click/h_attr · 138 h_event(16:58) · 139-141 b_sess/
   b_click/b_attr (burger) · 142-144 s_sess/s_click/s_attr (hunch)`.
   Index 138 ("b_event" in the brief) is a **hanafintech** event
   (`app_token=smxi7gqwu39c`, `package_name=in.hanafintech`), not burger.
2. **Burger data is NOT corrupt and its claims are correct.** b_sess (139),
   b_click (140), b_attr (141) parse cleanly (44/48/22 fields, 304-B blobs,
   tag OK, cert40 `F963DB904A1B9925C6C6444120FD2FCE2FF1F62A`) and their
   device H reproduces **byte-identically** from the wire maps (and had
   already verified from `cap/burger`). The reported "b_* fail" was the
   misalignment: the row tested as "b_event" was the hanafintech event at
   138 — and events genuinely failed (item 3).
3. **The event claims law is now SOLVED.** The signed map was never the
   problem — `build_claims` pinned `adj_signing_id` at the wrong place.
   The native pins `1300000` **before `seq`** (pool index of `seq`), not
   before `session_count`. One-line fix in `adj7_pure.py` line 147:
   `split = CLAIM_POOL.index("seq")`. With this law **all 21 ground-truth
   targets verify byte-identically** (below).

## 1. TASK 1 — burger verdict: (a)-corruption? NO. (b)-claims diff? NO.

Checks performed on b_* rows (and the whole stream):

* Stream framing: every POST body length == its Content-Length; the parser
  consumes all 237,464 B; all GET /attribution are bodyless as expected.
* All 12 adj7 tail blobs are 304 B, `verify_tag` OK (HMAC-DK37), records
  decrypt to sane JSON records (`a` 20-digit u64le, `b` 64-hex H,
  `c` per-app 40-hex cert: hanaf `C1BFAFCA…`, burger `F963DB90…`, hunch
  `AA92A187…`, consistent within each app), nonce12 = u64le(a)+d8 sane.
* Field counts match sibling sessions/clicks of the other apps
  (session 44-45, click 48-50, attr 22-23).
* H verification (law below): **139/140/141 MATCH**.

⇒ Definitive: burger never had a problem in this dump. Only the three
hanafintech *events* (130/134/138) failed — under the OLD law.

## 2. TASK 2 — the event claims law (root cause + proof)

### 2.1 Ground truth via the LSPosed hook (13:00 device run)

`work\modules_fresh.txt` / `lsposed_modules.log` / `oracle_logcat.txt` logged
`com.adjust.sdk.sig.Signer.sign(ctx, arg1, arg2, arg3)` plus the native
`nSign` call for the 13:00 session/click/attribution/event — including the
EXACT Java map handed to the native and the native's 304-B output blob.
Decrypted records give device H/nonce12/cert40 per request
(`hook_truth2.json`). Claims = pool concat of that exact map (+id+block2):

* click → **MATCH**, attribution → **MATCH** (and NO `language` — see §4)
* event → NO MATCH, even with the exact signed map in hand.

### 2.2 The native mint oracle

`adj7_work\adj7s3_emu.py` (Unicorn ARM64 emulation of the genuine
`libsigner.so` 3.62.0 `nSign`, interface `Emu().run(payload=b"\0"*32,
mapobj=dict, arg4=8)`, fully deterministic — same map ⇒ same blob/nonce).
Minting the hook maps confirmed: mint(click map) obeys the pool law,
mint(event map) does NOT ⇒ the transform is inside the native, driven by the
map content.

### 2.3 Bisection

* event map minus `event_token`/`event_count`/`callback_params`/
  `partner_params` → still transformed; minus **`seq`** → **pool law**.
* minimal map `{activity_kind, client_sdk, seq}` → pool law
  (`1300000`+`1`+`event`+`android5.6.0`).
* The real law: `seq`'s value belongs **after** the pinned `1300000`.
  `build_claims` had `seq` in the *profile* group (CLAIM_POOL lists `seq`
  immediately before `session_count`, and the split was at
  `session_count`), so it emitted seq's `1` before `1300000`. For maps
  **without** `seq` (every session/click/attribution) the two splits give
  identical strings — which is why only events ever failed.
* Order pinned by mint `{seq:1, session_count:7}`: `1300000`+`1`+`7`+
  block2 matches, `1300000`+`7`+`1` does not ⇒ seq is the FIRST tail key.

### 2.4 The corrected law

    split = CLAIM_POOL.index("seq")        # was: index("session_count")
    claims = vals(CLAIM_POOL[:split]) + "1300000" + vals(CLAIM_POOL[split:-2])
             + [activity_kind] + [client_sdk]          # block2 when included

(= `build_claims_v2` in `work\eb_audit\corrected_law.py`. No other change.)

### 2.5 Verification matrix — 21/21 byte-identical

| target | source | verdict |
|---|---|---|
| 13:00 hook click / attribution (exact nSign map + device nonce/cert) | hook log | MATCH / MATCH |
| 13:00 hook event (exact nSign map + device H `80FB8576…`) | hook log | **MATCH** |
| 13:00 event mint (native emu, own nonce/NUL cert) | unicorn mint | **MATCH** |
| dump 130 event (wire map, 15:39:16) | dev2srv dump | **MATCH** |
| dump 134 event (wire map, 15:47:43) | dev2srv dump | **MATCH** |
| dump 138 event (wire map, 16:58:46) | dev2srv dump | **MATCH** |
| all 15 session/click/attr of dump 127-144 (3 apps) | dev2srv dump | 15/15 MATCH |
| order pin `{seq:1, session_count:7}` | unicorn mint | seq-first confirmed |

Example (dump 138) tail of the claims string:
`…{"payrupik_c_id":"4c2576c7-…"}1300000`**`1`**`15151eventandroid5.6.0`
= id + **seq=1** + session_count=1 + session_length=5 + subsession_count=1 +
time_spent=5 + tracking_enabled=1 + block2. Full strings:
`work\eb_audit\event_claims_final.txt`.

## 3. Notes & corrections to earlier findings

* **No files were modified.** The fix is the one-liner in §2.4 to apply to
  `adj7_pure.py` (`build_claims`, line 147). Safe for every existing
  caller: claims strings are unchanged for seq-less maps (regression §2.5).
* The "attribution signs `language=en`" rule (ORACLE_FINDINGS §2) is
  **disproven**: `language` is not a CLAIM_POOL key (the oracle's
  `setdefault("language", …)` was a no-op), and the hook attribution with
  native `android5.6.0` client_sdk matches **without** any language value.
  All four dump attributions verify without it. `run_install*.py` /
  `adj7_oracle.py` language gating is harmless but dead code.
* Mint-oracle facts: deterministic per map; the record nonce12 comes from
  the emu's fixed-seed RNG (constant `d666bf34…` per process run) and
  `fixed_time` does not affect it; mint cert40 = 40 NULs (no-cert path) —
  H testing always used each target's own nonce/cert from its record.

## 4. Artifacts (work\eb_audit\)

`parse_dump.py`/`requests.json` (stream parse), `extract11.py`/`last11.json`,
`verify_all.py`/`verify_all.json` (old-law sweep), `event_targets.py`/
`event_targets.json`, `hook_truth.py`/`hook_truth2.json` (hook ground
truth), `mint_oracle.py`, `mint_probe.py`, `mint_bisect.py`,
`seq_layout.py`, `mint_minimal.py`, `mint_grow.py`, `seq_position.py`,
`twokey_hunt.py`, `determinism.py`, `corrected_law.py` (final battery),
`event_claims_final.txt`.
