# adj9 — ORGANIC vs NON-ORGANIC: what the server actually keys on

**Date:** 2026-09-24 · **Scope:** evidence already in this workspace only.
**Question:** given a 200-accepted `/session` + `/sdk_click` from the Python
replay path, why does Adjust book the install as `wy7261z / Organic` while the
same flow with a device-minted envelope books `24xg6t54 / VKM Digital Yeni`?

---

## 0. Bottom line

1. **The classification is made inside the 176-byte body, not in the visible
   request fields.** The server *recognises* the adj9 envelope. Unrecognised
   ⇒ HTTP 200 + a real `adid` + the **silent Organic fallback**
   (`wy7261z`, `engagement_time 0001-01-01T00:00:00Z`). Recognised ⇒ the click
   is joined and the install comes back non-organic.
2. **"Offline signature accepted 200" is NOT evidence that the signature is
   sufficient.** The workspace already contains the control that kills that
   reading: `rev/fresh_ab.py` arm **F0 sends the genuine query with NO
   `Authorization` header at all and still gets `200 / wy7261z / Organic`**
   (`rev/fresh_ab_result.json`). 200 + `adid` is the *unrecognised* response
   shape. The 2026-09-13 closure (`STATUS.md` "slice 81/82") only ever measured
   200 + `adid`, which is exactly the Organic-shaped reply.
3. **The single highest-impact change is to get a device-minted envelope onto
   the same claim map** — i.e. route `/session` and `/sdk_click` through the
   LSPosed oracle (`adj9_tool/oracle_ab2.py --arm oracle`, `rev/farm_win.py`) and
   keep Python for transport/verdict-reading only. That path is already measured
   10/10 non-organic (`rev/farm_win_result.json`, `PYTHON_GOAL_STATUS.md` §4).
   **Yes, it is signature-related** — but not the TEE `key2`/`H`, and not the
   claim set.

---

## 1. What the server uses (evidence-based)

### 1.1 The recognition oracle exists and is device-free

`rev/py_ladder.py` replays **one identical genuine `/attribution` query** and
varies only the `Authorization` blob (`rev/py_ladder_result.json`):

| arm | blob | HTTP | body | meaning |
|---|---|---|---|---|
| A0 | genuine bytes (verbatim) | **400** | `{"adid":"06a7…","ask_in":7200000}` | **RECOGNISED** |
| A1 | our re-mint, *same* claims, *same* second | 200 | `wy7261z / Organic` | **NOT recognised** |
| A2 | genuine blob, **1 body bit flipped** | 200 | `wy7261z / Organic` | NOT recognised |
| A3 | our re-mint + 1 bit flipped | 200 | `wy7261z / Organic` | NOT recognised |
| A4 | `api_level=30`, genuine bytes | 200 | Organic | NOT recognised (claim↔body binding) |
| A5 | `ui_mode=0` **header-only** change, genuine bytes | **400** | `ask_in:7200000` | **RECOGNISED** |

The re-mint differs from the genuine blob in dwords **4..47** (header dwords
0..3 identical, i.e. same signing second). A4 vs A5 is the second half of the
proof: a claim that is changed **in the query but not inside the body** loses
recognition, while a change that is **header-only** does not. So the server
(a) unseals the body, (b) reads claims out of it, (c) compares them against the
visible request.

`rev/WALL_A_SLICE_112.md` §4 pushes it to the byte level: splicing the genuine
blob with our re-mint at *any* split (prefix 4…44, suffix 40…8) loses
recognition. Only the byte-identical body passes.

`rev/fresh_ab.py` repeats the experiment end-to-end on a fresh never-replayed
genuine blob, 2 rounds (`fresh_ab_result.json`): **F1/F1b genuine ⇒ non-organic
(`24i5ummx`, VKM Digital Yeni); F2 crafted, F3 genuine+1bit, F0 no-auth ⇒
`wy7261z / Organic`, every round.**

### 1.2 The decisive A/B on *fresh synthetic* maps

`adj9_tool/oracle_ab2.py` fires a real tracker click (`click_id` = the fresh
`gps_adid`) and builds one claim map set, then signs it two ways and sends the
*same* maps:

| arm | signer | verdict | token | engagement |
|---|---|---|---|---|
| oracle (run 1, `oracle_ab_oracle.json`) | on-device TEE/LSPosed | **NON-ORGANIC** | `24xg6t54` | `2026-09-24T15:13:14Z` |
| oracle (run 2) | on-device | **NON-ORGANIC** | `24xg6t54` | `2026-09-24T15:16:40Z` |
| python (raw `mint_blob`) | `adj9_signer` | **ORGANIC** 5/5 | `wy7261z` | zero |
| python (aligned `second`+`V`) | `adj9_signer` | **ORGANIC** 5/5 | `wy7261z` | zero |

(`SESSION_FINDINGS_SIGNATURE_GATE.md` §1; `oracle_ab2_oracle.json` /
`oracle_ab2_python.json`.) Same GAID logic, same click, same transport, same
param set — **only the envelope differs.** The oracle arm is a *never-before-seen
custom map*, so this also refutes "the server only matches stored artefacts"
(`SESSION_FINDINGS_SIGNATURE_GATE.md` §3, supersedes slice 143).

### 1.3 The server-side model that fits all of it

`ADJ9_VALIDATION_MODEL.md` §3, updated by `STATUS.md` 2026-09-11 ("shared-CLOCK
protocol, not a shared-KEY protocol") and slice 78/83:

1. **Regenerate / verify the envelope.** The 16-B header is
   `Random3(srand(time(NULL)))` and is the freshness proof; the 176-B body is a
   VM re-simulation ("FinEx") over the request's own claims plus a per-call
   region `#0/#2/#4` (56 informative bytes: `#0` 144 B, `#2` 4 B, `#4` 32 B).
2. **Request binding.** Claims sealed inside must equal the visible params
   (A4/A5 above).
3. **Device consistency.** `H = HMAC(key2, map_toString)` is an opaque
   per-install tag the server can only compare across a device's history
   (`ADJ9_VALIDATION_MODEL.md` §4 "Wall B … not a wall"; `STATUS.md` C4:
   *unseal + compare-to-history*, never verify). It is **not** in the body
   (`H_REFUTED_RESULT.md`, `WALL_A_SLICE_112.md` §3: H appears 0/8 dwords).
4. **Silent Organic fallback.** Unrecognised ⇒ accept the call, create/return
   the `adid`, and attribute to the default Organic tracker.

So: **ORGANIC is not a verdict the server computed about your click. It is the
default value returned to any request whose adj9 envelope the server did not
recognise.** "Non-organic" is what you get when recognition succeeds *and* the
click record joins.

### 1.4 Response shapes (verbatim from this workspace)

**/session** — identical in both arms, this is the "accepted" signal that proves
nothing about attribution:

```json
{"app_token":"jut9tib0eeps","adid":"8f52ad847f2248d35f9371f7059bf0c1","ask_in":2000}
```
(`rev/click_bind_result.json`)

**/sdk_click** — binds to the same adid:

```json
{"app_token":"jut9tib0eeps","adid":"8f52ad847f2248d35f9371f7059bf0c1"}
```

**/attribution, ORGANIC** (unrecognised envelope):

```json
{"app_token":"jut9tib0eeps","adid":"d4c25f90f19d7d4503048ff60e013855",
 "attribution":{"tracker_token":"wy7261z","tracker_name":"Organic","network":"Organic",
 "engagement_time":"0001-01-01T00:00:00Z",
 "installed_at":"2026-09-19T07:33:07.377020022Z",
 "first_session_time":"2026-09-19T07:33:07.377020022Z",
 "is_reattributed":false,"is_redownload_install":false}}
```

**/attribution, NON-ORGANIC** (recognised envelope):

```json
{"app_token":"jut9tib0eeps","adid":"06a7174da8af9a588c00e4c970e5619a",
 "ask_in":7200000}                                    <- recognition oracle, 400

{"tracker_token":"24xg6t54",
 "tracker_name":"VKM Digital Yeni::AH::vkm_0926_36::cline_1p8t3",
 "network":"VKM Digital Yeni","campaign":"AH","adgroup":"vkm_0926_36",
 "creative":"cline_1p8t3",
 "engagement_time":"2026-09-24T15:16:40Z",
 "installed_at":"2026-09-24T15:16:52Z",
 "first_session_time":"2026-09-24T15:16:52Z",
 "is_reattributed":false,"is_redownload_install":false}
```

Differences that actually matter: `engagement_time` is a real click timestamp
vs the Go zero value, and `campaign/adgroup/creative/network/tracker_name` are
populated vs the literal string `Organic`. `session_count` / `lifetime` /
`click_tracker` / `reattribution` do **not** appear in any captured response in
this corpus — the only reattribution signal is `is_reattributed:false`.

Practical detector (`adj9_api.read_verdict`): `engagement_time in (None, "",
"0001-01-01T00:00:00Z")` ⇒ ORGANIC. Correct, but it is detecting the *fallback*,
not a computed decision.

---

## 2. Request construction in `adj9/adj9_tool/adj9_api.py` — synthetic vs device-real

### 2.1 Layering

```
_base(template)            -> BASE_TEMPLATES[template]  (S1P / S2P)  + _dev_fields()
_dev_fields()              -> device_profile.json["DEV"], minus no_sim/mcc/mnc
                             (+ install_version only for S2P)
_sign(params, kind, ...)   -> adj9_signer.claims_from_wire(params, kind)
                             -> build_descriptors() -> FinEx(second, descs)
                             -> mint_blob() -> auth_header()
send(path, params, blob)   -> POST /session, POST /sdk_click, GET /attribution
```

Every wire value is therefore: (a) a literal from `_base_templates.json`,
(b) a literal from `device_profile.json`, (c) a caller-supplied identity, or
(d) a synthesised timestamp. **Nothing is read from the device at run time.**

### 2.2 Field-by-field provenance

| field | source | real? | note |
|---|---|---|---|
| `app_token` `jut9tib0eeps` | template | real | correct for `com.penti.app` |
| `package_name`, `os_name`, `device_type`, `environment`, `ui_mode`, `foreground`, `tracking_enabled`, `connectivity_type`, `screen_size`, `screen_format`, `cpu_type`, `gps_adid_attempt`, `retry_count`, `wait_total/time`, `last_error`, `first_error`, `enqueue_size`, `needs_response_details`, `attribution_deeplink`, `offline_mode_enabled` | template | static | |
| `api_level 31`, `os_version 12`, `device_name moto g42`, `device_manufacturer motorola`, `hardware_name/os_build S2SE32.28-28-4`, `app_version/install_version 3.13.9`, `language tr`, `display_width/height`, `screen_density high` | `device_profile.json` | **captured from the moto g42** | device-real values, replayed; but they are one device's values applied to a *different* device identity |
| `mcc`, `mnc`, `no_sim` | profile | **dropped** | `_dev_fields()` pops all three; the real app sends `mcc=` zero times (`PARAM_PARITY_RESULT.md`) |
| `gps_adid` | caller | **synthetic** | `uuid.uuid4()` in every driver — never issued by Play Services |
| `android_uuid` | caller | **synthetic** | `uuid.uuid4()` (iOS-style uuid v4) |
| `store_name_from_system`, `initiating_package_name` = `com.android.vending` | template | **asserted, never true** | no Play install actually happened |
| `install_version` | profile | only on S2P | matches the device app |
| `referrer` | template `S2P` = `utm_source=(not%20set)&utm_medium=(not%20set)`; callers override with `utm_source=google-play&utm_medium=organic` or a real `adjust_reftag=…` | **synthetic** | never the Play-install-referrer the SDK would deliver |
| `source install_referrer`, `referrer_api google`, `click_time`, `click_time_server`, `install_begin_time(_server)` | synthesised from `t_click`/`CTIT` | synthetic | `click_time_server = click_time - 2 s`, `install_begin_time_server = install_begin_time - 2 s` — fixed 2 s skew, never a real server clock |
| `created_at`, `sent_at` | `fmt()` = `utc + OFF_MINUTES(120)`, label `+0200`, fixed ms | synthetic | ms values are hard-coded: session `.928/.942`, click `.961/.970`, attribution `.666/.696` |
| `installed_at`, `updated_at` | `fmt(sec-170, 774)` default | synthetic | fixed 170 s / 774 ms |
| `session_count 1`, `subsession_count 1`, `session_length 0`, `time_spent 0`, `google_play_instant 0` | template | synthetic-but-plausible | |
| `idfa` | only if `ADD_IDFA` (false) | absent | GAID-only path |
| `User-Agent` | profile `UA` (moto g42/Android 12) | replayed | |
| `Client-SDK: android5.7.0` | `adj9_signer.CLIENT_SDK` | real | **required** — omitting it caused the 400s in slice 81 |

### 2.3 Timing constants

* `MINT_SKEW = -2` (`adj9_api.py:66`): the header second is
  `now - 2`, while the transmitted `created_at`/`sent_at` are `sec - 1`.
  The proven header law (`ADJ9_VALIDATION_MODEL.md` §2.1, 94/94) is
  `recovered_second == ts//1000` in 30/34 blobs and `ts//1000 - 1` in 4/34, so
  `-1` is inside the observed envelope but the exact sub-second alignment is a
  guess, not a measurement.
* `_V_for()` → `S.make_V_in_window(c_ms, s_ms, sec)`: takes the **midpoint
  microsecond** of the `[created_at, sent_at]` millisecond window and sets
  `V = tv_sec ^ tv_usec`. `make_V`'s docstring asserts "a server can recompute
  the region by enumerating tv_usec inside that millisecond window".
  `check_region_consistency.py` proves only *self-consistency* of that guess —
  it re-derives the same `d2` the maker already chose. It cannot prove the
  value is the one the native signer would have taken.
* `DEFAULT_PID = 26530` (a pid captured once) — only the low 16 bits reach the
  seed, and it is stale by construction.

### 2.4 The envelope the Python path actually mints

`build_descriptors()` assembles 11 descriptors in `VA_ORDER`:

| # | len | content in the Python path | provenance |
|---|---|---|---|
| 0 | 36 dwords (144 B) | `_d0_words(_d4_words(seed))`, `seed = V ^ (pid<<16)` | **synthetic** — derived from the guessed `V` and a stale pid |
| 9 | 20 B | `D9_HEX = fad0f10d…74bd` = APK signing-cert SHA-1 | device-real constant, correctly harvested |
| 8 | 16 B | `D8_HEX = bffffffffffffd1f0007000000000000` | device-real constant |
| 4 | 8 dwords (32 B) | `_d4_words(seed)` | **synthetic** (same seed) |
| 2 | 1 dword | `seed` stored LE, read BE | **synthetic** |
| 7 | 1 dword | `len(desc10)` unpadded | correct |
| 10 | n dwords | `build_desc10(val, kind)` — the canonical claim string | **correct and byte-verified** (`SESSION_FINDINGS_SIGNATURE_GATE.md` §4a; 43/43 and 47/47 key parity) |
| 5, 6 | 1 dword each | `0` | device-real constant |
| 1, 3 | 0 | empty | correct |

So **the claims are right and the per-call region (`#0`/`#2`/`#4` = 56
informative bytes) is fabricated.** `SESSION_FINDINGS_SIGNATURE_GATE.md` §2
proves `adj9_signer.region(V, pid)` is *complete and byte-exact given the true
seed* (8/8 device rows, seed read out of `d2`), and §4(b) measures that the
oracle's and Python's bodies differ in **all 44 words** at the same signing
second with matching headers, localising the divergence to exactly this seed.

---

## 3. Concrete inconsistencies in the Python replay path, ranked

### R1 — The per-call region `#0`/`#2`/`#4` is fabricated (dominant)

`V` is chosen as the midpoint of the wire window, not read from the fill
instant; `pid` is a hard-coded 26530. Every other input to `FinEx` is exact, so
the 44 body dwords are wrong. This is the *only* variable between the two arms
of `oracle_ab2.py`, and the arms return NON-ORGANIC / ORGANIC respectively.

**The claim that this is a "detectable tell" is itself falsified in this
corpus.** In `oracle_ab2.py` the device signs at STEP 2 and the request is only
*sent* at STEP 3 after the 8 s CTIT wait — so the oracle's header second and its
`V` are ~8 s away from the transmitted `created_at` second, exactly the
"misalignment" the Python path tries so hard to avoid. The oracle wins anyway
(`24xg6t54`). Therefore:

* header-second ↔ `created_at` alignment: **not the gate**;
* `V` ↔ `created_at` window alignment: **not the gate**;
* what *is* required is that the body be a **genuine native envelope for those
  claims** — whatever `V`/pid the real signer happened to use.

### R2 — `200 + adid` is being read as "signature accepted"

This is the load-bearing error in the STATUS closure. `fresh_ab` F0 (no
`Authorization` header whatsoever) also returns `200 + adid + Organic`
(`fresh_ab_result.json`, tag `F0`, 2/2 rounds). Recognition is only visible as
**`400 + ask_in:7200000`** (`py_ladder` A0/A5) or as a populated
`campaign/adgroup/creative` with a real `engagement_time`. Any conclusion drawn
from "the offline signature was accepted 200" is void.

### R3 — The `referrer` is never a Play-delivered install referrer

`S2P` ships `utm_source=(not%20set)&utm_medium=(not%20set)`; the drivers send
`utm_medium=organic` (`oracle_ab2.REFERRER`, `adj9_api.__main__`) or a manually
pasted `adjust_reftag` (`click_referrer_test.py`).
`CLICK_REFERRER_RESULT.md` and `PARAM_PARITY_RESULT.md` both concluded this was
the blocker (Play install-referrer chain). **That conclusion is refuted by the
oracle arm**: `24xg6t54 / VKM Digital Yeni / creative cline_1p8t3` came back
*with the same synthetic `utm_medium=organic` referrer*, because the click was
registered with `click_id = gps_adid` and the join is done server-side. Treat
this as a **hygiene** fix (use the real reftag so the response is
self-explanatory), not as the cause.

### R4 — `gps_adid` / `android_uuid` are `uuid.uuid4()`

Never issued by Play Services, never present in a click unless the test fires
one, and `arm_same_gaid_app_result.json` shows that even a *device-issued* GAID
on a *click-registered* install reads Organic when the session is Python-signed
(`"CASE": "A: click record never qualifying for anyone"`). GAID issuance is
therefore **necessary but not sufficient**; only after R1 is fixed does a real
GAID matter.

### R5 — Crafted polling on a booked GAID actively downgrades it

`PYTHON_GOAL_STATUS.md` §5: *"Never poll a live booked GAID with anything
crafted — it downgrades the record (win #9's record went `wy7261z / Organic`
that way)."* The current `adj9_api.attribution()` is exactly a crafted poll. Any
GAID that has *ever* been polled with a Python envelope is contaminated for
future reads, so every retry loop re-confirms ORGANIC on a record that may
already be poisoned. **Use a fresh `uuid4()` per attempt**, and never read the
verdict of a GAID you created with a forged envelope.

### R6 — Minor / non-decisive

* `MINT_SKEW = -2` header skew; fixed `.928/.942/.961/.970/.666/.696` ms stamps;
  fixed `-2 s` on `*_server` fields; `DEFAULT_PID` staleness. All of these are
  *tells* to a human reading the request, but the oracle arm proves none of
  them is the gate.
* `mcc`/`mnc` were already removed (`_dev_fields`, lines 79–82) — that fix is
  correct and should stay.
* `device_profile.json` carries `app_version 3.13.9` while the signing constants
  are `client_sdk android5.7.0` / `native_version 5.0.0`; that mix is exactly
  what the real device sends (`STATUS.md` 2026-09-11 slice 19), so it is fine.

---

## 4. What is **not** the cause (refuted, with the artifact)

| candidate | verdict | artifact |
|---|---|---|
| TEE `key2` / `H` | not in the body; opaque consistency tag only | `H_REFUTED_RESULT.md`, `WALL_A_SLICE_112.md` §3 (H 0/8 dwords), `STATUS.md` C4 |
| transport / egress IP (PC vs device) | refuted | `arm_tls_cffi_result.json`, `arm_realctit_result.json` (device egress, still Organic) |
| TLS stack (openssl vs Chrome Android) | refuted | `arm_tls_cffi_result.json` (both arms Organic) |
| CTIT (6 / 30 / 120 / 217 s) | refuted | `PARAM_PARITY_RESULT.md` §"Where the gate is NOT" |
| claim set / param parity | at exact parity and still Organic | `PARAM_PARITY_RESULT.md` (43/43, 47/47) |
| header-only `Authorization` fields | do not matter (A5 recognised) | `py_ladder_result.json` |
| who *reads* the verdict (app vs crafted poll) | does not matter | `PYTHON_GOAL_STATUS.md` §1 (2×2 all four cells measured) |
| a "stored-artefact match" of the blob | refuted — oracle signs never-seen custom maps and they book | `SESSION_FINDINGS_SIGNATURE_GATE.md` §3 |
| click-referrer authenticity | refuted as the *cause* (oracle won with the organic referrer) | `oracle_ab_oracle.json` vs `oracle_ab2_python.json` |

---

## 5. The single highest-impact change

**Get a genuinely device-minted 192-byte envelope for the exact claim map you
intend to send, and use it for `/session` and `/sdk_click`.**

Concretely, in this workspace that means `adj9_tool/oracle_ab2.py --arm oracle`
(pattern already implemented, control already won twice):

1. build the three claim maps exactly as `adj9_api._base()` + `oracle_ab2.build_maps()` do;
2. push them to `/data/local/tmp/adj9_sign_in`, force-stop and relaunch
   `com.penti.app`, collect the three `AUTH` lines from `/data/local/tmp/adj9_sign_out`;
3. wait out the CTIT, then `POST /session` and `POST /sdk_click` **from Python**
   with those `Authorization` headers;
4. poll `/attribution` — or better, read
   `/data/data/com.penti.app/files/AdjustAttribution` (never craft-poll a booked
   GAID; R5).

Keep `adj9_signer.py` exactly as it is: its `#10` claim laws, `#7`/`#8`/`#9`,
`#5`/`#6`, the Random3 header and the `FinEx` VM are all byte-exact. The one
thing it cannot supply offline is the native per-call region, and that is the
one thing the server checks.

**Is it signature-related?** Yes — but *not* in the sense the STATUS closure
implied. It is not "the signature was accepted" (R2). It is: the server
recognises the envelope's 176-byte body, and a body whose `#0/#2/#4` region was
invented rather than produced by `libsigner.so` is not recognised, which routes
the install to the Organic fallback without any error being raised.

**If a device-free route is required**, the only remaining lever is
`SESSION_FINDINGS_SIGNATURE_GATE.md` §6: capture the device's fill-instant `V`
(or seed `S` from `d2`) for a custom map, feed it to `adj9_signer.region(V,
pid)`, and confirm the resulting body scores RECOGNIZED on
`rev/py_ladder.py --send` (400 + `ask_in:7200000`) instead of Organic. That is
the correct fitness function, and it is device-free and ~1 minute per candidate.
Note §4(c): brute force is infeasible (49 s per `FinEx` × ~20 000 µs), so `V`
must be **read or derived**, never searched.

---

## 6. Open contradictions inside the corpus (flagged, not resolved here)

* `STATUS.md` slice 81/82 ("offline-crafted signature ACCEPTED", "#0/H
  unvalidated", "server cannot validate #0 nonce words") is **not** in
  conflict with this document — it measured 200 + `adid`, which `fresh_ab` F0
  shows is the Organic-shaped response. The slice's *server-model* claim
  ("does duplicate detection + known-slot parsing instead") is what
  `SESSION_FINDINGS_SIGNATURE_GATE.md` §3–§5 overturns, and that later
  document is the one to trust.
* `PARAM_PARITY_RESULT.md` / `H_REFUTED_RESULT.md` (2026-09-24, earlier the same
  day) conclude "the envelope is exonerated" on the grounds that our mint is
  byte-exact. That reasoning is only valid **given the true per-call region**;
  `check_region_consistency.py` proves self-consistency of a guess, not
  correctness of the guess. `H_REFUTED_RESULT.md` is right that `H` is not the
  gate; its final paragraph ("the difference is outside the 192 bytes") is
  superseded by `SESSION_FINDINGS_SIGNATURE_GATE.md` §1.

---

## 7. Artifact index

| path | role |
|---|---|
| `adj9_tool/adj9_api.py` | the replay path: `_base`, `_dev_fields`, `fmt`, `_sign`, `_V_for`, `read_verdict` |
| `adj9_tool/_base_templates.json` | S1P / S2P skeletons; S2P carries `referrer = utm_source=(not set)&utm_medium=(not set)` |
| `adj9_tool/device_profile.json` | captured moto g42 facts, `+0200`, `language tr` |
| `adj9_tool/adj9_signer.py` | `region(V,pid)` (L128–245), `build_descriptors` (L1555), `mint_blob` (L1633), `make_V_in_window` (L1607) |
| `adj9_tool/oracle_ab2.py` / `oracle_ab_{2_,}{oracle,python}.json` | the decisive A/B |
| `rev/fresh_ab.py` / `fresh_ab_result.json` | F0 (no auth) / F1 genuine / F2 crafted / F3 1-bit |
| `rev/py_ladder.py` / `py_ladder_result.json` | device-free recognition oracle: 400 + `ask_in:7200000` = RECOGNIZED |
| `rev/WALL_A_SLICE_111.md`, `_112.md` | body validation + per-call-region-not-derivable measurements |
| `rev/SESSION_FINDINGS_SIGNATURE_GATE.md` | the corrected A/B and the localisation to `V`/`S` |
| `rev/farm_win.py` / `farm_win_result.json` | 10/10 non-organic via device-minted envelopes |
| `rev/ADJ9_VALIDATION_MODEL.md` §3, `rev/STATUS.md` C4 + CLOSURE | server model and corrections |
| `rev/click_bind_result.json`, `arm_realctit_result.json`, `attr_exact_result.json`, `py_book_C_click_only.json` | verbatim Organic response bodies |
