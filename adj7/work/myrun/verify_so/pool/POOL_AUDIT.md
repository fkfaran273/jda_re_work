# POOL_AUDIT.md -- claim-pool audit of `adj7/work/myrun/adj7_pure.py`

Offline, read-only except this dir. Reference binary: 3.62.0 arm64 `libsigner.so` (`adj7/apks_hanafintech/libsigner.so`).
My-run copy imported directly; decrypt/H reimplemented here (not prior verdicts).

## 1. .so inventory

| file | md5 | size |
|---|---|---|
| `adj7/apks_hanafintech/libsigner.so` | B00FA453F379843CED688676CA677622 | 1145112 |
| `adj7_work/bins/.../arm64-v8a/libsigner.so` | B00FA453F379843CED688676CA677622 | 1145112 |
| byte-identical | True | |

## 2. Pool dump vs myrun CLAIM_POOL

Raw XOR decode at file `0x1169B0`, key `0x16`, terminator raw `== K` (`0x116ee8`): 98 keys, head `ad_impressions_count,ad_revenue_network,ad_revenue_placement`, tail `tracking_enabled,updated_at,activity_kind,client_sdk`.

| check | result |
|---|---|---|
| key count (.so / myrun) | 98 / 98 |
| order-identical (element-for-element) | True |
| missing in .so | none |
| extra in .so | none |
| reordered | none |
| `secret_id` position (.so / myrun) | 80 / 80 |
| `adj_signing_id` pool member (.so / myrun) | False / False |

Literals: `1300000` @`0x113E10` k=`0x43`; `adj_signing_id` @`0x113E28` k=`0xBB`; standalone `secret_id` @`0x113E00` k=`0xB5` -- all decode as listed in sec 1 log lines above (recheck stdout lines `lit ...`).

## 3. `1300000` pin position (functional grid, hanaf session)

Pin inserted at candidate positions on the hanaf session map (`pin=<key>` = emit before that pool key; `pin=session_count` output asserted byte-equal to myrun `build_claims()` inside the run). `pin=seq` MATCHes here too, but that is degenerate: the session map carries no `seq`, and `seq` is the last profile key, so before-`seq` emits the pin at the identical claims position as before-`session_count`. The degeneracy is broken by the event map (`seq=1` present) in sec 5, which moves the split one key earlier -- see verdict sec 7.

| pin position | claims len | H match? |
|---|---|---|
| None | 376 | MISMATCH |
| start | 383 | MISMATCH |
| seq | 383 | MATCH |
| session_count | 383 | MATCH |
| session_length | 383 | MISMATCH |
| end | 383 | MISMATCH |

## 4. Per-kind per-source H verification (myrun copy, own decrypt)

`hanaf_nsign` = `hanaf_map.json` nSign map as-is (already carries `activity_kind`+`client_sdk`); `payrupik_wire` = wire body/URL-query + `activity_kind`+`client_sdk=android5.6.0`. Nonce/cert40 from own record decrypt (AES-256 inverse written here; CBC roundtrip asserted per blob; nonce12/record_b cross-checked vs `hanaf_verify.json`, same values).

| kind | source | H match? | claims len |
|---|---|---|---|
| session | hanaf_nsign | MATCH | 383 |
| session | payrupik_wire | MATCH | 383 |
| click | hanaf_nsign | MATCH | 579 |
| click | payrupik_wire | MATCH | 579 |
| attribution | hanaf_nsign | MATCH | 207 |
| attribution | payrupik_wire | MATCH | 211 |
| event | hanaf_nsign | MISMATCH | 350 |
| event | payrupik_wire | MISMATCH | 350 |

Record detail (own decrypt):

| kind | source | a | d | cert40 |
|---|---|---|---|---|
| session | hanaf_nsign | 15784143748510265713 | 4D9B4DDA | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |
| session | payrupik_wire | 10519674177386270295 | E4B94D81 | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |
| click | hanaf_nsign | 724394539793106051 | 385234C9 | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |
| click | payrupik_wire | 8019694652585369438 | 51C145A2 | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |
| attribution | hanaf_nsign | 13106841944429420300 | 98457008 | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |
| attribution | payrupik_wire | 12137478147332815070 | 85006809 | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |
| event | hanaf_nsign | 2840104665878199822 | 4159A65C | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |
| event | payrupik_wire | 5078348138406896382 | 4BF3438A | C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF |

## 5. Event residual SOLVED: pin sweep (pool-key resolution)

Full activity_kind x client_sdk x pin grid: 160 variants (8 ak-values x present/absent sdk x 5 pins x 2 sources), 2 hits -- both `activity_kind='event'` + `client_sdk` present + pin before `seq` (hanaf event AND payrupik sid45, independent nonces/maps). No activity_kind or client_sdk variant matches under the old before-`session_count` pin.

Focused pin sweep on both event sources (as-is maps, `activity_kind/event` + sdk present):

| source | pin before pool key | H match? | claims len |
|---|---|---|---|
| hanaf | os_version | MISMATCH | 350 |
| hanaf | package_name | MISMATCH | 350 |
| hanaf | params | MISMATCH | 350 |
| hanaf | partner_params | MISMATCH | 350 |
| hanaf | payload | MATCH | 350 |
| hanaf | secondary_dedupe_token | MATCH | 350 |
| hanaf | secret_id | MATCH | 350 |
| hanaf | seq | MATCH | 350 |
| hanaf | session_count | MISMATCH | 350 |
| hanaf | session_length | MISMATCH | 350 |
| hanaf | None | MISMATCH | 343 |
| hanaf | start | MISMATCH | 350 |
| hanaf | end | MISMATCH | 350 |
| payrupik | os_version | MISMATCH | 350 |
| payrupik | package_name | MISMATCH | 350 |
| payrupik | params | MISMATCH | 350 |
| payrupik | partner_params | MISMATCH | 350 |
| payrupik | payload | MATCH | 350 |
| payrupik | secondary_dedupe_token | MATCH | 350 |
| payrupik | secret_id | MATCH | 350 |
| payrupik | seq | MATCH | 350 |
| payrupik | session_count | MISMATCH | 350 |
| payrupik | session_length | MISMATCH | 350 |
| payrupik | None | MISMATCH | 343 |
| payrupik | start | MISMATCH | 350 |
| payrupik | end | MISMATCH | 350 |

Pool indices: `partner_params`=68, then all-absent run 69-80 (`partner_sharing_settings`..`secret_id`), `seq`=81, `session_count`=82. The MATCH set {payload, secondary_dedupe_token, secret_id, seq} is exactly the claims-degenerate set: pin emitted after the `partner_params` value and before the `seq` value. The old split (before `session_count`=82, i.e. after the `seq` value) MISMATCHes on both sources. Regression check (run log): pin-before-`seq` leaves session/click/attribution claims byte-identical to myrun `build_claims()` and MATCHing on both sources (`seq` absent there).


Rodata context: the string-table cluster `0x113C00-0x114400` decoded with exactly the nine known single-byte-XOR keys (no brute force, no false positives) is listed in full in the run log; activity-ish members were folded into the candidate list above. No rodata activity string was needed: the event residual is fully explained by pin position (sec 5), with activity_kind='event' + client_sdk present as in the captured maps.

## 6. Per-install fields

| map | secret_id | app_secret |
|---|---|---|
| hanaf session | False | False |
| hanaf click | False | False |
| hanaf attribution | False | False |
| hanaf event | False | False |
| payrupik session | False | False |
| payrupik click | False | False |
| payrupik attribution | False | False |
| payrupik event | False | False |

Native string-table refs (XOR-encrypted, so plaintext-absent by design; cf. `SO_VERIFY.md` sec 2 keyword group): `secret_id` decodes as pool key #80 plus a standalone literal @`0x113E00`; `adj_signing_id` standalone literal @`0x113E28`. Map-level: neither `secret_id` nor `app_secret` appears in any of the 8 oracle maps, so no hidden per-install claims input exists on observed traffic; pool membership already handles a future map carrying them.

## 7. Final verdict

**pool CONFIRMED, pin-split CORRECTED** -- (a) .so pool string is 98 keys, order-identical to myrun `CLAIM_POOL` (no missing/extra/reordered key); (b) the `"1300000"` pin split is NOT before `session_count`: event H MATCHes on both independent sources iff the pin is emitted after the `partner_params` value and before the `seq` value, and MISMATCHes at the old split. Exact correction in `adj7/work/myrun/adj7_pure.py:build_claims`: `split = CLAIM_POOL.index("seq")` (pool index 81) instead of `CLAIM_POOL.index("session_count")` (pool index 82). Any split key in the all-absent run {`partner_sharing_settings`..`secret_id`, indices 69-80} is behaviourally identical on observed traffic; `seq` is the canonical choice (first pool key after the gap). Session/click/attribution are unaffected (`seq` absent from their maps: claims byte-identical, still MATCH). `secret_id`/`app_secret` absent from all 8 oracle maps.

