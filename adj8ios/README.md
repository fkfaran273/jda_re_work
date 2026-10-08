# adj8ios — the Adjust **adj8** signature on **iOS** (SDK ios5.6.2 / native 3.67.0)

Port of the `adj8` (Android) + `adj9_ios` pattern to the adj8 generation on the
iOS SDK. Pure Python, self-contained, **byte-exact against genuine device
blobs** — 15/15 frozen vectors, three different apps, four request kinds.

```
python adj8ios_pure.py          # selftest: 15/15 byte-exact vs genuine blobs
python run_verify.py <capture>  # carve + verify a capture (.saz or .chls)
python make_gold.py             # re-carve the captures, rebuild gold_vectors.json
python make_py27_adj8ios.py     # regenerate + self-check the three _py27 files
python replay_attr_test.py      # the replay-rule proof (sends live requests)
python run_install.py --dry-run # sign all three requests, send nothing
```

## The law

```
blob(176) = header(16) || body(128) || tag(32)

header    iOS MINSTD: x = (second mod 2^31-1), 0 -> 1; 8 draws x = 16807*x mod p;
          w_i = d[2i]^d[2i+1], big-endian  (16 B)
record    01 00 08 | head16[3:19] | 02 | S BE32[20:24] | 03 | d9 = 00*20[25:45]
          | 04 | block32[46:78] | 05 | sha256("")[79:111] | 06 | 02 | 0f*15[113:128]
head16    the d0 selector head for seed S, selector phase (0x09,)  -- identical
          construction to adj9_ios (same _d4_words/_d0_words path)
block     sha256_iv2( d9 || 00 08 || head16 || LE32(S) || sha256("") || 0x02 || claims )
claims    pool-order values, bare-concatenated:
          POOL_MAIN values (present keys only) || "1400000"
          || POOL_REST values || activity_kind || client_sdk || "9" || "3.67.0"
body      AES-256-CBC over the record; key = ffb5e5f9…0db3, IV = header
tag       HMAC-SHA256(DK38, body), DK38 = caab8344…728f

auth      Signature signature="<BASE64>",adj_signing_id="1400000",
          algorithm="adj8",headers_id="9",native_version="3.67.0"
```

### activity_kind per request kind

| endpoint | activity_kind in the claims |
|---|---|
| `/session` | `session` |
| `/sdk_click` | `click` |
| `/attribution` | `attribution` |
| `/sdk_info` | **`info`** (not `sdk_info`) |
| `/event` | `event` (not yet confirmed on a capture) |

### What is shared with adj8-Android, and what is iOS-only

| piece | adj8 Android | adj8 iOS | evidence |
|---|---|---|---|
| AES-256 key, CBC, IV = header | yes | **same key** | iOS record decrypts under it, 28/28 |
| tag = HMAC-SHA256(DK38, body) | yes | **same DK38** | 28/28 capture blobs |
| claims pool + split at `session_count`, pin `adj_signing_id` | yes | **same law** | 15/15 full blobs |
| SHA-256 chained from IV2 | yes | **same IV2** | (adj9-iOS has a *different* IV2) |
| header | bionic rand, 31-word taps r[3]+r[0], 310 warm-up, 8 draws | **MINSTD 8 draws** (adj9-iOS generator) | seed inversion, every blob |
| head / d0 selector phase | masks 131…145 (phase 0x40) | **phase (0x09,)** | 28/28 heads |
| record variant byte `record[112]` | `0x01` | **`0x02`** | every iOS blob |
| cert slot `record[25:45]` | real cert SHA-1 | **20 zero bytes** | every iOS blob |
| blob size / padding | 176 B, `0f*15` | same | |

So adj8-iOS = adj8-Android's crypto + claims core, with iOS's own header
generator, d0 phase, variant byte and empty cert slot.

### client_sdk in the claims

The claims carry the **full client-sdk header value**, verbatim:

| app | client-sdk |
|---|---|
| com.Neon.MindAI (web bridge) | `web-bridge5.6.2@ios5.6.2` |
| com.ma.waveapp (react native) | `react-native5.6.0@ios5.6.2` |
| com.niceonesa (plain iOS SDK) | `ios5.6.2` |

## Verification record

| capture | blobs | record layer (AES+tag+head) | full 176 B |
|---|---|---|---|
| `neomindios_adjust.saz` (Fiddler) | 4 | 4/4 | **4/4** click, session, attribution ×2 |
| `wave_19may_install_newapp_ios8.chls` (Charles) | 6 | 6/6 | **5/6** (+1 event, see open item) |
| `niceoneiosauto_6may_lvl2_ios11.chls` (Charles) | 18 | 18/18 | **6/18** (see open item) |
| **total** | **28** | **28/28** | **15** |

1. **Structure** — every blob decrypts to the 128-byte record above under the
   adj8-Android AES key with IV = header.
2. **Tag** — `HMAC-SHA256(DK38, blob[16:144])` reproduces the trailing 32 B on 28/28.
3. **Header** — the MINSTD inverse (seed ±15 min around the request's own
   `sent_at`) yields a **unique** second for every blob checked.
4. **Head** — `head16_for(S, (0x09,))` reproduces `record[3:19]` on 28/28. The
   phase matters: with the Android phase `(0x40,)` only 14 of 16 bytes match —
   the first halfword is the folded selector `0x09`, i.e. mask 21 = `(9<<1)+3`.
5. **Claims** — byte-exact on 15/15, from (params, activity_kind, client_sdk)
   alone, spanning four activity kinds and three apps.

## Server gate proven (replay rule, 2026-10-08)

`replay_attr_test.py` takes the genuine exchange out of
`wave_19may_install_newapp_ios8.chls` and re-sends it through our signature:

| step | logged | ours | |
|---|---|---|---|
| `POST /session` | `adid 06e6c45f…`, `ask_in:2000` | `adid 06e6c45f…`, `ask_in:5000` | same device (only the server's poll cadence differs) |
| `POST /sdk_click` | `adid 06e6c45f…` | `adid 06e6c45f…` | **identical** |
| `GET /attribution` | `tracker_token: unattr`, `tracker_name: No User Consent`, `engagement_time 2026-05-19T11:47:39Z`, `installed_at/first_session_time 11:50:32Z` | **every field identical** | **MATCH** |

The negative control is the part that matters: the *same* request with **one
flipped tag byte** comes back `tracker_token: 1ut7ge7s`, `tracker_name: Organic`,
`engagement_time 0001-01-01` — the silent Organic fallback. Adjust therefore
validates the DK38 tag, and our mint passes it; the attribution object we get
back is the genuine device's, not a default.

(`run_install_result.json` / `replay_attr_result.json` hold the raw bodies. Note:
`/session` rate-limits at one per 20 min per adid — re-running within the window
returns `400 request check interval failed`, which is *not* a signature failure.)

## Live install — BOOKED, on both Python versions (2026-10-08)

`run_install.py` fired through the team's tracker
`clicks.appsatiate.com/api/track/v1/click?aff_id=2&offer_id=312066` (which 302s
to the Adjust tracker `1x6tr630`, campaign `GWM_43241_161`, adgroup
`43241_stm_`), then sent a **signed** session → attribution for a fresh device.

**Python 3 / curl_cffi:**

```
idfa 6854665D-…   idfv F4F6016B-…   att_status 3
[session]      200 {"app_token":"mrpexk5wqp6o","adid":"44df9f76cddb4c263f700988e95cc338","ask_in":2000}
[attribution]  200  tracker 253botf4
                     name    globalwidemedia::GWM_43241_161::43241_stm_::{sub_id}
                     engage  2026-10-08T10:44:58Z     is_reattributed false
VERDICT: BOOKED 253botf4
```

**Python 2.7.18 / stdlib httplib:**

```
idfa 9D378CA2-…   idfv 997328F9-…   att_status 3
[session]      200 {"app_token":"mrpexk5wqp6o","adid":"f9cc406fad01ee633e09cc406f2da56a","ask_in":2000}
[attribution]  200  tracker 253botf4
                     name    globalwidemedia::GWM_43241_161::43241_stm_::{sub_id}
                     engage  2026-10-08T10:59:58Z     is_reattributed false
VERDICT: BOOKED 253botf4
```

So the adj8-iOS mint is accepted end-to-end on **both** interpreters and **books a
non-organic conversion** — the first booked install from an adj8 iOS signature,
and the backend's own Python needs no py3-only dependency. `{sub_id}` in the
tracker name is the tracker's own unsubstituted `creative={sub_id}` placeholder,
not something the signature controls.

Note: appsatiate refuses repeat clicks from this IP (`400 {"error":"not able to
server ad"}`) after the first, so the 2.7 run used the Adjust link the tracker
had issued; the runner accepts either form, retries the tracker through a
cooldown (`CLICK_TRIES` / `CLICK_RETRY_WAIT`), and warns loudly instead of
silently going Organic.

### `sub3` = device-matched click

The tracker forwards `sub3` straight into the Adjust link as `idfa=`, so the
runner appends its own fresh idfa to the hardcoded link (verified:
`sub3=X` -> `idfa=X` in the `Location`). That is what makes the click
device-matched:

```
[click] GET http://clicks.appsatiate.com/api/track/v1/click?aff_id=2&offer_id=312066
        &sub3=6620C1B6-1E0D-4CC8-81B7-0155D75F6ED5
[click] Adjust /1x6tr630 | campaign=GWM_43241_161 adgroup=43241_stm_ click_id=0YRFSwkHHO7ZgUnym05ONB
[click] device-matched idfa=6620C1B6-1E0D-4CC8-81B7-0155D75F6ED5 ip=106.219.165.14
[click] Adjust click: 200
[session]      200 adid b5581fc528c8fa317739d558ef19d6ab
[attribution]  200 {
 "app_token":"mrpexk5wqp6o","adid":"b5581fc528c8fa317739d558ef19d6ab",
 "attribution":{"adgroup":"43241_stm_","campaign":"GWM_43241_161","creative":"{sub_id}",
   "engagement_time":"2026-10-08T11:14:58Z","first_session_time":"2026-10-08T11:15:44Z",
   "installed_at":"2026-10-08T11:15:44Z","is_reattributed":false,
   "is_redownload_install":false,"network":"globalwidemedia",
   "tracker_name":"globalwidemedia::GWM_43241_161::43241_stm_::{sub_id}",
   "tracker_token":"253botf4"},
 "skadn_coarse_value":"low","skadn_conv_value":0,"skadn_lock_window":false}
VERDICT: BOOKED 253botf4
```

With `sub3` the response carries the full attribution object (campaign, adgroup,
creative, network) plus the SKAdNetwork block — versus the unlinked replay, which
only ever returns `unattr` / `No User Consent`.

## Python 2.7 build (AutoLabs backend)

`make_py27_adj8ios.py` regenerates `adj8ios_pure_py27.py`, `run_install_py27.py`
and `_py27_transport.py` from the py3 sources — never edit the `_py27` files by
hand. Verified on this machine's real **Python 2.7.18**:

```
py -2.7 adj8ios_pure_py27.py     -> self_test: 15/15 byte-exact
py -2.7 run_install_py27.py --dry-run  -> 176 B blobs, all three kinds
```

Transforms: `bytes.fromhex` → `bytearray.fromhex`, `bytes(...)` → a `_b()` shim
returning a bytearray (so iteration yields ints on 2.7), `int.from_bytes` /
`.to_bytes` → `struct.unpack` / `struct.pack`, `.hex()` → `binascii.hexlify`,
`urllib.parse` → a `urlparse`/`parse_qsl` fallback, `datetime.timezone` →
`utcnow`, `print(…, flush=)` → a `say()` helper, `curl_cffi` → `_py27_transport`.

Two things the 2.7 path needs that py3 hides:

1. **`Content-Type` must be set explicitly on POST.** `curl_cffi` infers
   `application/x-www-form-urlencoded` from `data=<dict>`; stdlib `httplib` does
   not, and Adjust then parses an empty body and answers `{}` (session 200 with
   no adid, attribution 400). Symptom of hitting this: an empty `{}` session.
2. **The shim must be scheme-aware.** A hardcoded `HTTPSConnection` cannot reach
   an `http://` tracker URL, and `resolve_click()` needs `.headers` to read the
   `Location` of the tracker's 302.

## Files

| file | what |
|---|---|
| `adj8ios_pure.py` | **the signer** — `sign_request(fields, kind, c, second=, nonce4=)` → the finished Authorization header; `self_test()` proves 15/15 |
| `adj8ios_pure_py27.py` | the same signer on Python 2.7 (generated; **verified 15/15 under real 2.7.18**) |
| `make_py27_adj8ios.py` | regenerates all three `_py27` files, then self-checks them (rejects py3-only constructs and byte-compiles under real 2.7) |
| `run_install.py` | the funnel: [click + `sub3=idfa`] → signed `/session` → signed `/sdk_click` → signed `/attribution`; `--dry-run` signs without sending |
| `run_install_py27.py` | the funnel on 2.7 (stdlib httplib transport; TLS impersonation is py3-only) |
| `_py27_transport.py` | scheme-aware httplib shim for 2.7 (`.status_code/.text/.json()/.headers/.url` + redirect following) |
| `replay_attr_test.py` | the replay-rule proof: logged exchange vs ours, with a corrupted-tag control |
| `campaign_data.py` | the three campaigns in the AutoLabs backend's nested shape |
| `gold_vectors.json` | the 15 frozen genuine blobs + params/second/S (rebuild with `make_gold.py`) |
| `make_gold.py` | re-carves the captures, inverts the header seed, refreezes the verified set |
| `carve.py` | capture carving + verification primitives (`.saz` via zipfile, `.chls` by regex) |
| `run_verify.py` | `python run_verify.py <file.saz\|file.chls>` → per-blob tag/head/block table |
| `event_search.py` | the shared oracle (SHA-256 state cached over the fixed preimage prefix) |
| `event_search2.py`, `event_search5.py` | the single-edit and preimage-shape searches for the `/event` gap |
| `click_diag.py` | probes the appsatiate click endpoint — proves `aff_id=2 / offer_id=312066` is valid and that the `400` is a per-IP burst cooldown |
| `replay_attr_result.json`, `run_install_result.json` | raw bodies from the last replay / live run |

**The captures are not kept here** — the originals are in
`C:\Users\Apps\Downloads` (`neomindios_adjust.saz`,
`wave_19may_install_newapp_ios8.chls`, `niceoneiosauto_6may_lvl2_ios11.chls`,
44 MB together). `make_gold.py` reads them from there by default; override with
`CAPTURES="a.saz;b.chls"`. `*.saz` / `*.chls` are git-ignored.

## Open item: `/event` claims

13 of the 28 blobs have a verified record (AES, tag, head seed) but their claims
do not reproduce — after fixing the carving bugs, what is left is exactly the
three `/event` requests (wave #6, niceone #7 and #18). The bodies are fully
visible in plaintext in the `.chls`, and the preimage is demonstrably the same
shape, so this is a real gap in the claims content.

Ruled out by search (all negative):

| hypothesis | how it was tested |
|---|---|
| wrong `activity_kind` | `event`, `click`, `session`, `attribution`, `info`, `sdk_info`, `unknown`, `initiated_by`, … plus "absent" |
| a pool key the SDK omits | drop every 1-combination and 2-combination of the present pool keys |
| an extra/missing value | single insert / delete / replace at every offset — **604,079 candidates over the 556 B claims, no fit** |
| a value in the wrong slot | single-value *move* to every other offset |
| a value not in the wire params | every `t\x00<len>` string frame the `.chls` stores near the request — the event name (`add to wishlists`), URL, host, header values |
| a different preimage | all 256 variant bytes, variant omitted, and an extra 16-byte descriptor (adj9-ios' `dev` field) in 4 shapes |

All negative — including the string-frame pass, which was the last class of
candidate the earlier sweeps could not reach.

Since a single edit cannot explain it, the event branch differs in **two or more**
places at once — most plausibly `event_token` / `event_count` / `seq` handling
combined with the activity_kind token. `adj9_ios` has no event vector to borrow
from (its three frozen vectors are session / click / attribution).

Closing it properly needs the **3.67.0 iOS libsigner** binary to read the event
branch, the way `adj7_work` did for the Android native. Nothing in the install
funnel depends on it: `run_install.py` does not send events.

The Charles carving bugs found along the way are fixed in `carve.carve_query()`
and were worth recording in their own right:

1. the sweep pulled the framing key into the last value — `att_status=0sq`,
   `att_status=0q`, `att_status=0t`;
2. `str.isalnum()` is `True` for latin-1 letters (`æ`, `ÿ`), so payload bytes
   joined the query;
3. long bodies are sometimes stored base64, truncating the visible params.

Fixing those moved the `.chls` verification from 2/24 to 11/24.

The runner and the py2.7 build are done (`run_install.py --dry-run` signs all
three requests; `py -2.7 adj8ios_pure_py27.py` is byte-exact 15/15), and both
book live.
