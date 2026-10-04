# _sub_ios_mint_RESULT.md — iOS adj9 mint: final law, /event claims law, self-test score

Date: 2026-10-01. Assets: `adj9_signer.py` (read-only), capture
`C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz`,
stage-1/2 artifacts (`_sub_unseal_core.py`, `_sub_unseal_ios_out.json`,
`_sub_ios_header.py`, `_sub_ios_seconds.json`), the parallel agent's
`_sub_android_event_RESULT.md` + `_sub_event_signings.json`.
New scripts this stage: `_sub_ios_np_sha256.py`, `_sub_ios_claims_probe.py`,
`_sub_ios_claims_search.py`, `_sub_ios_claims_quick.py`, `_sub_ios_npsearch.py`,
`_sub_ios_framescan.py`, `_sub_ios_framescan2.py`, `_sub_ios_bigsearch.py`,
`_sub_ios_subset.py`, `_sub_ios_seconds.py`, and the packaged
**`_sub_ios_mint.py`** (self-contained minter; imports adj9_signer primitives,
modifies nothing).

---

## 0. TL;DR score

| check | result |
|---|---|
| Android gold vectors, full 192-B mint through this module's pipeline | **9/9 byte-exact** |
| iOS capture headers reproduced from the recovered signing seconds (MINSTD law) | **30/30** |
| iOS capture digest MAC (shared key K) | **30/30** |
| iOS d0 head == `region(S, head=(0x40,))` | **30/30** |
| iOS record rebuild — every non-claims field byte-exact | **30/30** |
| iOS full 192-B mint | **0/30** — diverges exactly at record byte 46 (the BLOCK) |

The **only** unsolved piece is the iOS claims payload inside the BLOCK
pre-image. Everything around it — header law, seed law, record container,
all three iOS record deviations, whitening, digest — is proven 30/30. A
~15-million-hypothesis search over (message frame × claims composition) found
zero BLOCK matches; the exhaustive negative results are in §4. Until the iOS
claims string is pinned (an ios-simulator frida trace, like the Android
`adj9/device/` traces, would settle it in one signing), `mint_ios` accepts a
`claims=` override and otherwise emits the best-known law whose output
matches each captured blob for the first 48-50 of 192 bytes (header + the two
whitened chunks before the BLOCK enters the CBC chain) and diverges precisely
at the BLOCK.

## 1. THE FINAL iOS LAW (end-to-end, verified parts marked)

```
blob(192) = header(16) || whiten(record(144), header) || digest(32)
```

**header (VERIFIED 30/30)** — Apple MINSTD (Park–Miller), NOT the Android
bionic law:

```
x    = unix_sec mod (2^31-1);  if x == 0: x = 1
D[0] = x;  D[k] = 16807*D[k-1] mod (2^31-1), k = 1..8
w_i  = D[2i] ^ D[2i+1]                 (i = 0..3, over the 8 post-step draws)
header = BE32(w0)||BE32(w1)||BE32(w2)||BE32(w3)
```

Signing seconds recovered 30/30 by inverting this law (±900 s around
ClientBeginRequest, always unique; `make_ios_header(second) == blob[:16]`
30/30). Header collisions exist only at the 1970/2038 epoch edges.

**region (VERIFIED 30/30)** — shared with Android: `region(S, 0, 0, head)`;
the record's `S` is `rec[20:24]` big-endian and the d0 head is
`head16_for(S, (0x40,))` — the pure `0x40|(i&7)` selector cycle entered at
index 0 (Android requests used the literal phase `(0x2B,)`; the phase is a
free value).

**record (VERIFIED 30/30 with the deviations below)**

```
01 00 08 | head16 | 02 | BE32(S) | 03 | D9 | 04 | BLOCK |
05 | sha256("") | 06 02 07 | device_name+00*pad(16) | 0000 | 0e*14
```

The **three iOS record deviations** vs Android:

1. descriptor-6 variant byte @112 = **0x02** (Android `0x01`);
2. D9 (cert SHA-1) @25..44 = **20 zero bytes** (no APK cert on iOS; constant
   across all 30 records);
3. the 16-B descriptor-7 field @114..129 carries the **device name**
   (`iPhone13,2`, zero-padded; `device_name=iPhone13%2C2` on the wire) —
   Android has 16 zero bytes.

**BLOCK (recipe verified on Android 354/354; iOS payload UNRESOLVED)**

```
BLOCK = sha256_customIV2( D9 || 00 08 || head16 || LE32(S) || sha256("") ||
                          variant(02) || device_field(16) || claims )
```

`sha256_customIV2` = standard SHA-256 compression chained from
`IV2 = eba2c435...f1355ea5` (the signer's `sha256_iv2`). On Android the last
two fixed bytes are `rec[112] || rec[114:130]` (indistinguishable there from
the constant `01 || 00*16`); the iOS form substitutes the two record
deviations — but no tail/claims combination tested reproduces the capture's
BLOCK (§4).

**digest (VERIFIED 30/30)** — shared double-padded MAC over the whitened body
with secret K.

**adj_verification (VERIFIED)** — `BASE64(b"Quoh8uafohgh7CahM2h" cycled XOR
compact JSON '{"os_name":"<os>"}')`; this capture is an ios-simulator build
(`KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb`); a real device sends
`make_adj_verification("ios") = KlcAG2cbAAsKSl1KXiwSSjA=`.

## 2. The /event claims law (Android — proven; iOS expected to mirror)

Derived independently here from the on-device instrumentation maps
(`_sub_event_signings.json`) and confirmed by the parallel agent's frida-trace
proof:

```
profile block : sorted(PROFILE + SESSION_EXTRA
                       + ['event_count','event_token','partner_params'] present)
pinned        : adj_signing_id -> "1500000"        (emitted, never map-read)
tail block    : sorted(SESSION_TAIL + ['seq'] present)
envelope      : [activity_kind, client_sdk, headers_id, native_version] present
claims        = ''.join(values).encode('latin1')   (bare values, no separators)
```

* Placement is load-bearing: `event_count`/`event_token`/`partner_params`
  sort into the PROFILE group (before the pinned id) — `partner_params`
  lands between `package_name` and `push_token`; `seq` sorts into the TAIL
  group (after the pinned id, before `session_count`).
  seq-in-profile and event-keys-in-tail both fail the BLOCK oracle.
* Proven here: **91/91** penti android5.7.0 event signings (block-hash
  equality); parallel agent: **27/27** byte-exact full mints.
* Calibration: the same machinery reproduces the known kinds on the same
  traces **183/183 session, 171/171 click**, plus the 9 embedded gold
  vectors — the verification pipeline is sound.
* For iOS the pool extends with `callback_params` (the 5.8.0 rename of
  `partner_params`); `event_count`, `event_token`, `seq` are already the
  capture's own key names.

## 3. The packaged minter — `_sub_ios_mint.py`

```python
import _sub_ios_mint as m
blob, auth = m.mint_ios(kind, params, unix_sec=None, S=None,
                        device_name="iPhone13,2", os_name="ios",
                        claims=None, head=(0x40,), variant=0x02,
                        d9=b"\x00"*20, client_sdk=None)
# kind: session|click|attribution|event; params: decoded wire fields;
# claims: explicit bytes/str override (needed until the iOS claims law is
# pinned); returns (blob192, 'Signature signature="...",adj_signing_id="1500000",
# algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="..."')
```

Also exposed: `make_ios_header`, `invert_ios_header`,
`make_adj_verification`, `desc10_keys_ios`, `build_claims_ios`,
`build_record_ios`, `block_message_ios`, `predict_block_ios`.

`python _sub_ios_mint.py --selftest` output (score):

```
android gold full-blob mints (shared pipeline): 9/9
iOS capture headers reproduced at recovered seconds: 30/30
iOS capture digest MAC (shared K): 30/30
iOS d0 head == region(S, phase (0x40,)): 30/30
iOS record rebuild, non-claims fields byte-exact: 30/30
iOS full-blob mint: best 50/192 bytes byte-exact (0/30 full) — BLOCK claims law unverified
```

## 4. The iOS BLOCK/claims negative results (what was tried)

Oracle: `sha256_iv2(prefix || claims) == rec[46:78]` on all 30 records
(representative record per kind first, then full-kind verification on any
hit). Harness validated end-to-end on the 9 Android golds (9/9) before use.

**Message frames (~800 variants):**

* D9 slot: 20 zero bytes, empty.
* magic slot: `rec[1:3]` (00 08), `rec[0:2]`, `rec[0:3]`, literal `00 08`/`01 00`, device field.
* head16 slot: `rec[3:19]`, pairwise-swapped, byte-reversed, BE/LE d0-word
  packings, `head16_for(S,(0x2B,))`, the 16-B blob header itself.
* S slot: LE32, BE32, LE/BE of the signing second, LE/BE of the MINSTD state
  x, omitted entirely, swapped with head16, 64-bit forms.
* SHA256("") slot: as-is, device field, device field before/after it.
* TAIL slot: `01||00*16` (Android const), `02||device_field` (record-sourced),
  `02||00*16`, `01||device_field`, `02||"iPhone13,2"` (unpadded),
  `01||"iPhone13,2"`, `rec[111:130]` (06 02 07+dev, 19 B), `rec[112:130]`
  (02 07+dev, 18 B), `06||dev`, `07||dev`, `06 02||dev`, dev-only(16 B),
  `01||00*16||dev`, `02||00*16||dev`, `02 07||00*15`; device field as claims
  suffix/prefix; no-S and reordered topologies.

**Claims compositions (each × frames):**

* Android presence law (`desc10_keys`/`build_claims` semantics) over the iOS
  params, all four kinds — including the IOS_VERIFICATION.md 11-key session
  law (`app_token, app_version, created_at, device_name, device_type,
  environment, installed_at, os_name, os_version, adj_signing_id,
  session_count`) — with the event extension placements from §2.
* iOS-name law (`bundle_id`, `idfa`, `idfv` sorted into the profile).
* Canonical-name translation (`android_uuid`=idfv, `gps_adid`=idfa,
  `package_name`=bundle_id) — sorted and as separate placements.
* Synthesized values: `hardware_name`="iPhone13,2", `tracking_enabled`="1",
  `country`="US", `adj_verification` (b64 and plaintext-JSON forms),
  `activity_kind`, `client_sdk`="ios5.8.0", `headers_id`="10",
  `native_version`="5.0.0", `algorithm`="adj9", adid
  (`baa52143f2b91a6ce1c1e04aa3c15ca1`) as android_uuid/gps_adid/first/last.
* Toggle subsets: 12-15 independent profile toggles × tail subsets × pinned
  (after-profile/at-end/absent) × block2 subsets × app_version
  ↔ app_version_short value swap — vectorized with a numpy SHA-256
  (`_sub_ios_np_sha256.py`, validated exact vs the signer), ~15M hashes on
  the session record alone (1.57M compositions × 16 frames), similar for
  click/attribution/event.
* Orders: sorted (key), raw wire order (consistent per kind — verified),
  iOS keys at group boundaries, bundle_id after created_at.
* Serializations: bare values (Android-proven), `k=v&...`, `k=v` concat,
  `k=v;`, `k=v\n`, `k:v`, values joined by `&`/`\n`; raw body/query string as
  claims; length-prefixed claims (2-B/4-B BE/LE); dword-padded claims (the
  descriptor-#10 padding rule); device field (with NUL padding) as an
  interior claims value; self-referential BLOCK candidates
  (sha256/iv2 over body/record/header combinations — all fail).

**Conclusion:** the iOS claims string is not any composition of the request's
observable values in the tested laws/orders/frames. Since the Android
signing map is proven to be exactly the body params + 7 wire-free extras
(slice-107 §5), and the server must re-derive the claims from the request,
the most probable explanations are (a) an iOS-specific claims value the
capture cannot show — e.g. the SDK's persisted install uuid (the
`android_uuid` analog) carried in the map but not on the wire — or (b) an
iOS-only serialization detail. One ios-simulator frida hook on
`sha256_iv2`-equivalent code (or on the claims materialization) resolves it
immediately; `mint_ios(claims=...)` is ready to reproduce the capture
byte-exactly the moment the string is known.

## 5. Artifacts (all new files; nothing existing modified)

* `_sub_ios_mint.py` — the packaged minter + self-test (`--selftest`).
* `_sub_ios_seconds.json` / `_sub_ios_seconds.py` — per-request recovered
  signing seconds (30/30 unique) + record field cross-checks.
* `_sub_ios_np_sha256.py` — numpy-vectorized sha256-IV2 batch oracle
  (validated exact vs `adj9_signer.sha256_iv2`, ~30 µs/candidate).
* `_sub_ios_claims_probe.py`, `_sub_ios_claims_search.py`,
  `_sub_ios_claims_quick.py`, `_sub_ios_npsearch.py`, `_sub_ios_framescan.py`,
  `_sub_ios_framescan2.py`, `_sub_ios_bigsearch.py`, `_sub_ios_subset.py` —
  the §4 search ladder.
* Logs: `_sub_ios_npsearch_out1.log`, `_sub_ios_bigsearch.log`.
