# SO_VERIFY.md — independent re-verification of the adj7 law straight from libsigner.so

Date: 2026-10-06. Scope: `adj7/work/myrun/adj7_pure.py` (the myrun signer copy)
against native `libsigner.so` binaries. Offline only; no network, no replays.
Nothing outside `adj7/work/myrun/verify_so/` was created or modified.

## 1. .so inventory (size / md5)

| file | size | md5 | identity |
|---|---|---|---|
| `adj7/apks_hanafintech/libsigner.so` (arm64-v8a) | 1145112 | B00FA453F379843CED688676CA677622 | 3.62.0 (hanaf device build) |
| `adj7_work/bins/adjust-android-signature-3.62/jni/arm64-v8a/libsigner.so` | 1145112 | B00FA453F379843CED688676CA677622 | byte-identical to hanaf copy |
| `adj7_work/bins/adjust-android-signature-3.62/jni/x86_64/libsigner.so` | 1085720 | CE79575E4EF16D9F73D7E0129F212FB3 | 3.62.0 x86_64 |
| `adj7_work/bins/adjust-android-signature-3.62/jni/x86/libsigner.so` | 1121808 | C4921C8EB9C90DED7B010B06479A8EB0 | 3.62.0 x86 |
| `adj7_work/bins/adjust-android-signature-3.62/jni/armeabi-v7a/libsigner.so` | 1070500 | 23B8AF5234D53E94FCF6E0B97CCACA1C | 3.62.0 arm32 |
| `adj7/apks/lib/libsigner.so` (arm64-v8a) | 983864 | F5F6C80DBDBD44BD5B69A562FCF24637 | **3.61.0** (nirio device build; cf. `adj7/README.md:111-113`) |
| `adj7/work/devemu/bins/adjust-android-signature-3.62/jni/arm64-v8a/libsigner.so` | 983864 | F5F6C80DBDBD44BD5B69A562FCF24637 | byte-identical to 3.61.0 copy (dir name is misleading) |
| `adj9/rev/creditsea/libsigner.so` | 1366632 | DBE36C643D174F1CCA240DCEC1F4C585 | other app build, not used |

Reference binary for all offsets below: the 3.62.0 arm64 `.so`
(`adj7_work/bins/.../arm64-v8a/libsigner.so`, == hanaf copy).
String law used: per-string single-byte XOR `raw^K`, terminator = raw byte `== K`
(recovered in `adj7_work/adj7b_pool3.py`; pool DB `adj7_work/adj7b_pool3_out.json`).
Disassembler: NDK `llvm-objdump`/`llvm-readelf`.

## 2. Per-component verdict

| component | .so evidence | matches myrun `adj7_pure.py`? | refs |
|---|---|---|---|
| blob layout 16+256+32 | single `rand`-pair loop + 16-chunk body + one tag; JNI exports exactly `nSign`/`nOnResume`; dynamic traces show 304-B blobs | CONFIRMED (functional: sid44 rebuild byte-exact) | `law_recheck.py` output §4 |
| header: srand(time-second) | `.dynamic` imports `srand`+`rand`+`time` from LIBC; code: `bl time@plt` (file 0xde99c) immediately followed by `bl srand@plt` (0xde9a0); no other RNG import (`random`/`lrand48` absent) → exactly one header variant on Android | CONFIRMED (structure + functional) | readelf JMPREL: `rand` GOT 0x117cb0, `srand` 0x117cc0, `time` 0x117cb8 |
| header: rand-pair + EOR loop | two `bl rand@plt` per iteration (0xba52c, 0xba54c, results pushed via VM op 0x110978), loop-back `cbnz → 0xba528`; after loop two VM pops then `eor w2,w0,w21` at 0xba598 | CONFIRMED (structure; trip counts 310/8 confirmed functionally — the loop bound is a VM constant, not a native immediate) | disasm 0xba528-0xba5b8 |
| header big-endian words | `make_header` equality vs all 4 hanaf blobs (`make_header(created_at-second)==blob[:16]` per `ORACLE_FINDINGS.md` §3) | CONFIRMED | `adj7/work/ORACLE_FINDINGS.md:156-158` |
| SEED `f110fb41…654b` | NOT visible statically: no `mov` half-immediate of any SEED half-word anywhere in `.text`; no single-byte-XOR blob either. Provenance is dynamic: round keys K1..K14 captured in Unicorn traces, SEED back-solved through the standard AES-256 schedule (`work/seed_hunt.py`: expansion of seed reproduces K1..K14 14/14), body byte-exact on 2 unicorn mints (`work/spn_law2.py:349-369`) | CONFIRMED (dynamically + functionally; statically opaque by design — no AES S-box exists anywhere in the image either, `work/SPN_FINDINGS.md:121-130`) | `adj7/work/SPN_FINDINGS.md:120-130`, `seed_hunt.py`, `spn_law2.py:119-135` |
| DK37 `2a4cc079…ef591eb` | all 8 words as `mov w2,#lo16` / `movk w2,#hi16,lsl#16` immediates feeding VM push op 0x110978, file 0xcc43c-0xcc5bb: `0x2a4cc079` (0xcc43c/0xcc448), `0x60d64762`, `0x3cc386dc`, `0xefafbf25`, `0xb669914d`, `0x32cc8585`, `0xa1ed7f92`, `0x0ef591eb` (0xcc5a8/0xcc5b4) | CONFIRMED byte-exact (myrun `DK37.hex()` equals this word sequence) | disasm 0xcc43c-0xcc5c0; prior note `SPN_FINDINGS.md:63-64` |
| tag = HMAC-SHA256(DK37, blob[16:272]) | `verify_tag` TRUE on all 7 genuine blobs (3 payrupik sids + 4 hanaf calls); keyword strings `macSHA256`, `SecretKeySpec`, `androidKeyStore` present in .so | CONFIRMED | `law_recheck.py` §4; pool3 DB `keyword` group |
| IV0 `16ba6d02…08ec3bec` | NOT visible statically (no immediates, no XOR blob). Provenance is dynamic: heap snapshot shows 8 single-block SHA-256 runs keyed with init `16ba6d02…` at heap 0x900be98 (`COMMIT_FINDINGS.md` §1); same IV0 verifies emulator mints + OnePlus 7 (niri) + moto g42 (hanaf) → generation-wide in practice | CONFIRMED (dynamically + cross-device functionally) | `adj7/work/COMMIT_FINDINGS.md:51-74` |
| commitment msg layout `prefix\|\|nonce12\|\|sha0hex\|\|claims`, std SHA-256 | W-words recovered algebraically from traces spell the message text (`commit2_wextract.py`); cert40-prefix (not 00*40) proven by 3/4 hanaf MATCH vs 0/4 with 00*40 | CONFIRMED | `COMMIT_FINDINGS.md:66-73`, `hanaf_verify.json` |
| cert40-ASCII vs 00*40 selection | .so reads the app cert itself: keyword strings `getApkContentsSigners`, `signingInfo`, `etSigningCertificateHistory`, `KeyStore`, `etPrivateKey`, `adjust_keys`, `GETcERTIFICATEcHAIN` all present; record `c` on hanaf == cert SHA-1 `C1BFAFCA…2C6DF`; emulator no-cert path yields 40 NULs | CONFIRMED (both branches observed in genuine records) | pool3 DB `keyword` group; `hanaf_verify.json` `record_c` ×4 |
| record JSON format, A/D8/`\x00`+`0x10` pad | 4/4 hanaf bodies decrypt (SEED schedule) to 256-B records parsing as `{ "a": <u64> ,"b": "<H>" ,"c": "<cert40>","d": "<D8>","e": "<SHA0>" }\x00` + `0x10` pad; `nonce12 = u64le(a) \|\| hex(d)` feeds H | CONFIRMED | `hanaf_verify.json:7-11,81-86,160-165,211-216` |
| claims pool keys AND order | .so holds ONE comma-joined pool string, file 0x1169b0, XOR key 0x16, 98 keys starting `ad_impressions_count,ad_revenue_network,…` (the pool3 DB entry at 0x1169c5 missed the head word — raw decode from 0x1169b0 gives the full string). Decoded key list == myrun `CLAIM_POOL` element-for-element (order + membership, `secret_id` between `secondary_dedupe_token` and `seq`, tail `…updated_at,activity_kind,client_sdk`) | CONFIRMED exact (98/98, order-identical) | §3 below |
| `"1300000"` pin at `session_count` split | literal `1300000` in .so string table (0x113e10, key 0x43, NUL-terminated); pool has NO `adj_signing_id` key; `adj_signing_id` exists only as a standalone literal (0x113e28, key 0xbb) → pin model is the only consistent reading; session/click/attribution MATCH with pin, mismatch without (prior grids) | CONFIRMED | raw decode §2 |
| activity_kind/client_sdk tail | both are the last two pool keys in the .so string; `+block2` maps already carry them so `include_block2` is a no-op on captured maps; sid44 rebuild uses block2 | CONFIRMED | pool string tail |
| auth tail `adj_signing_id="1300000"`, `algorithm="adj7"`, `headers_id="8"`, `native_version="3.62.0"` | every literal XOR-encrypted in the 3.62.0 .so: `adj_signing_id` (0x113e28,k0xbb), `1300000` (0x113e10,k0x43), `algorithm` (0x113e48,k0x74), `adj7` (0x113e60,k0xdb), `headers_id` (0x113e18,k0x7c), `native_version` (0x113e38,k0xf0), `3.62.0` (0x113e58,k0x2d) — all NUL-terminated | CONFIRMED (literals live in the native string table, not only in Java) | raw XOR scan §2 |
| cipher: textbook AES-256 expansion, measured ShiftRows, NO final SubBytes | `spn_chunk` closed form byte-exact on both unicorn mints (`spn_law2.main`); 4/4 hanaf records decrypt with it to valid JSON | CONFIRMED | `spn_law2.py:119-166`, `hanaf_verify.json` |
| secret_id / app_secret per-install fields | `secret_id` IS a pool key in the .so (pool position 76) and has a second standalone literal (0x113e00,k0xb5, near `adj_signing_id`) — i.e. the native reads it from the map when present; but `secret_id`/`app_secret` appear in NONE of the 4 captured nSign maps (`secret_id_in_map=false` ×4) and session/click/attribution verify from the visible map alone → no hidden per-install claims input | CONFIRMED absent on the wire; pool membership handled correctly by myrun copy | `hanaf_verify.json:65-66,144-145,196-197,274-275`; `ORACLE_FINDINGS.md:129-137` |
| timestamp/encoding variants | `.dynamic` imports `localtime`+`strftime`+`gettimeofday` (GOT 0x117d08/0x117d10/0x117d18) → local-offset `…Z+0530` timestamp construction, matching `ORACLE_FINDINGS.md` §4 (claims carry the local-offset strings verbatim; header seed = `created_at` second for all 4 calls) | CONFIRMED, no variant | readelf JMPREL |
| second header variant | exactly one `srand` site and one rand-pair loop in 3.62.0 arm64; x86/x86_64 additionally carry inline Park-Miller immediates (`imul …0x41a7`, `add …0x7fffffff` at x86_64 file ~0xf99b0-0xf9a73 — bionic-compatible LCG for non-Android targets). No MINSTD path in the Android .so (iOS `native_variant` is out of scope) | none found | disasm; x86_64 hex context |

## 3. Claim-pool proof (the `secret_id` question)

Raw decode of 3.62.0 arm64 `.so` at file 0x1169b0 with key 0x16 up to the
terminator gives a 98-key comma-joined string whose `.split(',')` equals
`myrun/adj7_pure.py:64-86 CLAIM_POOL` element-for-element (`exact order match:
True`). In particular the .so pool **contains `secret_id`** (between
`secondary_dedupe_token` and `seq`) and **starts with `ad_impressions_count`**.

Consequences:

- The myrun copy pool is byte-exact vs the 3.62.0 native. No correction needed.
- The top-level `adj7/adj7_pure.py` pool (97 keys, no `secret_id`) **diverges from
  the native** by omitting `secret_id` (`adj7_pure.py:64-86` vs myrun
  `adj7_pure.py:64-86`; sets differ by exactly `{'secret_id'}`). Functionally
  silent on all observed traffic (no map carries `secret_id`), but a fresh mint
  whose map contained `secret_id` would mis-verify under the top-level copy.
  (Not in myrun scope; flagged for the owner.)
- Cross-version note: the 3.61.0 `.so` (`adj7/apks/lib`, XOR key 0x66) embeds an
  85-key pool — a strict subset of the 98-key 3.62.0 pool in the same relative
  order (missing 13 keys: `ff_app_set_id_disabled`, `ff_att_disabled`,
  `ff_idfv_disabled`, `ff_odm_enabled`, `initiating_package_name`,
  `last_skan_update`, `odm_info`, `order_id`, `originating_package_name`,
  `seq`, `store_app_id_from_client`, `store_name_from_client`,
  `store_name_from_system`; still includes `secret_id`). The myrun copy targets
  3.62.0 (hanaf: `native_version="3.62.0"`, `headers_id="8"`) and its pool is
  the 3.62.0 pool — correct pairing. Do NOT "fix" the myrun pool toward 3.61.0.

## 4. `law_recheck.py` output (myrun signer copy, verbatim)

```
pool has secret_id: True
sid 42 tag_ok=True
sid 43 tag_ok=True
sid 44 tag_ok=True
sid44 byte-exact rebuild with patched signer: True
sid 42 claims bytes=383 act=session
sid 43 claims bytes=579 act=click
sid 44 claims bytes=211 act=attribution
```

## 5. Fresh-mint hunt (anything that would verify differently on a fresh nonce+time)

- Extra claim keys: none. The .so pool is fully enumerated (98 keys, §3); every
  key of all 4 hanaf nSign maps is either in-pool or in the known-skipped set
  (`adj_signing_id`, `algorithm`, `headers_id`, `native_version`, `wait_total`,
  `foreground`, `connectivity_type`, `cpu_type`, `retry_count`, `screen_size`,
  `wait_time`, `first_error`, `sent_at`, `offline_mode_enabled`,
  `screen_density`, `ui_mode`, `enqueue_size`, `gps_adid_attempt`,
  `device_manufacturer`, `display_width`, `needs_response_details`,
  `screen_format`, `last_error`, `attribution_deeplink`, `display_height`,
  `language`, `session`-only `partner_params` is in-pool, etc.). No map key
  exists that the native would consume but the myrun copy would skip, or vice
  versa.
- Per-install fields: `secret_id`/`app_secret` absent from all 4 nSign maps;
  both are pool keys so a future map carrying them is handled at the .so pool
  position. No other install-scoped literal found (string-table sweep covers
  the `0x113df0-0x113f40` field-name cluster).
- Timestamp variants: single path (`time()` seed; `localtime`/`strftime`
  local-offset rendering). Header seed = `created_at` second on all 4 calls.
- Event residual: the event call's outside-pool key set is the same innocuous
  set as the MATCHING session call (no event-only key), so the open event
  mismatch is not explainable by a missing pool key or an extra consumed field
  visible in the map — it remains a value-snapshot-level residual, unchanged by
  this verification. No .so evidence suggests any claims-law change for events.

## 6. Final verdict

**CONFIRMED** — no divergence found in the myrun copy. Every recorded constant
(SEED, DK37, IV0 words, 98-key pool + order, `secret_id` membership,
cert40/00*40 selection, bionic-rand header construction, auth-tail literals
`"1300000"`/`"adj7"`/`"8"`/`"3.62.0"`) is grounded in the 3.62.0 `.so`
(directly: DK37 immediates, pool string, auth literals, import/call structure;
via traces + byte-exact rebuilds where the native white-box hides the value:
SEED, IV0, trip counts). No correction to `adj7/work/myrun/adj7_pure.py` is
required. Two adjacent observations (no action in myrun): top-level
`adj7/adj7_pure.py` omits `secret_id` from its pool (diverges from both natives'
pools); `adj7/work/devemu/bins/.../arm64-v8a/libsigner.so` is the 3.61.0 binary
despite its `3.62` directory name.
