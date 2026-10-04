# SIGGATE INVESTIGATION — why the app resolves non-organic and Python resolves Organic

Date: 2026-09-24 (device ZD2228MY3X disconnected; offline analysis + one PC-side
live experiment). Author: reverse-engineering/teammate. All claims below cite
bytes or files.

**Verdict up front: the discriminator is (B) — a transport-provenance signal —
narrowed to the TLS client / HTTP-stack fingerprint of the signed Adjust calls
(the one variable never held constant in any experiment to date).** (A) is
exhausted claim-by-claim; (C) is refuted by a same-mechanism pairing on the
same device within minutes. Details and the one decisive experiment below.

---

## 1. Winning-request anatomy

### 1.0 Provenance of the "winning capture" — an important correction

`penti_android_test.saz` (the 2026-09-14 "M4" winning triple) is treated
everywhere as device ground truth. Its Fiddler metadata says the TCP client of
ALL six sessions was `python:14056` @ `::ffff:127.0.0.1`
(`rev/_saz_x/raw/{1..6}_m.xml`, `x-processinfo`/`x-clientip`). This is NOT a
re-attribution of the win to Python:

- TEST_LOG.md §3 defines M4 as an **on-device** run ("hooked, fresh AAID
  `d016e7e4`, full-funnel Fiddler capture" → NON-ORGANIC `24pxw9rl` VKM).
- Sessions 4–6 are traffic no team script emits: `POST
  api-p1.penti.com.tr/.../oauth/token` with `User-Agent: okhttp/5.3.2`, and
  Firebase RemoteConfig with a real Firebase-installations JWT and
  `X-Android-Cert: FAD0F10D60F93C17937B2F1EB6C09691AE7D74BD` — the genuine
  Play signing cert, the same 20 bytes as signature descriptor #9
  (`mint_pipeline.py:60`). No file in `rev/*.py` references `api-p1` or
  firebase (grep: 0 hits).
- The sdk_click carries `click_time_server = click_time − 2 s`,
  `install_begin_time_server = install_begin_time − 2 s` — Play-server clock
  skew "not our +1s fabrication" (TEST_LOG.md §4).

So the .saz is the real app's bytes relayed to Fiddler through a python
process on the PC (capture plumbing), and — critically — **every capture we
have of a winning request is a MITM'd leg**. The app's direct-to-server TLS
ClientHello and ALPN/h2 framing have never been observed. The 9-24 g42 wins
(`device/fresh_click_install_g42.py`) were not packet-captured at all; the
verdict was read from `/data/data/com.penti.app/files/AdjustAttribution`
(`G42_WIN_RESULT.md`).

### 1.1 The winning triple (M4, SAZ sessions 1–3, 2026-09-14 12:23 UTC)

POST `https://app.adjust.com/session` — headers **in order**
(`rev/_saz_x/raw/1_c.txt`):

```
Client-SDK: android5.7.0
Authorization: Signature signature="<256 b64 = 192 B>",adj_signing_id="1500000",
               algorithm="adj9",headers_id="10",native_version="5.0.0",
               adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
Content-Type: application/x-www-form-urlencoded
User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)
Host: app.adjust.com
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: 1027
```

Body: 43 form params in the order preserved in `rev/saz_params.json`
(`store_name_from_system` first … `tracking_enabled` last), `quote_plus`
encoding (`moto+g42`, `%3A`, referrer double-encoded `%2520`). Response:
`200 {"app_token":"jut9tib0eeps","adid":"2fedfd3dfcc48e92aae70f3fd2e1608a",
"ask_in":2000}`.

POST `/sdk_click`: same header block, `Content-Length: 1284`, 47 params
(`api_level` first), referrer `utm_source=(not%20set)&utm_medium=(not%20set)`,
`click_time_server = click_time − 2 s`, `install_begin_time_server =
install_begin_time − 2 s`. Response 200, same adid.

GET `/attribution?<22 params>` — headers: `Client-SDK`, `Authorization`,
`User-Agent`, `Host`, `Connection: Keep-Alive`, `Accept-Encoding: gzip` (no
Content-Type/Length). Response (`rev/_saz_x/raw/3_s.txt`):

```json
{"attribution":{"tracker_token":"24pxw9rl",
 "tracker_name":"VKM Digital Yeni::AH::vkm_0926_36::penti_generic",
 "network":"VKM Digital Yeni","engagement_time":"2026-09-14T10:25:58Z",
 "installed_at":"2026-09-14T12:23:08Z", ...}}
```

Note: the joined engagement (10:25:58Z) is ~2 h BEFORE the install and equals
NEITHER the sdk_click's declared `click_time` (12:18:35Z) nor any call in the
capture — the join key was the GAID `d016e7e4-…` matched server-side against a
click record the ad network already held. The 9-24 g42 wins differ: there the
engagement_time equals the team's own device-fired curl click
(09:07:49Z vs installed 09:07:55Z; 10:15:02Z vs 10:15:07Z —
`G42_WIN_RESULT.md`, `TRANSPORT2_RESULT.md` §3), so a synthetic curl click
**does** join when the app sends the session.

---

## 2. Python-vs-app request diff

Python send path: `mint_pipeline.api_session_mint / api_sdk_click_mint /
api_attribution_mint` → `adj9_full_chain.send` (`adj9_full_chain.py:255-299`,
raw `http.client` with explicit `putheader` order).

| layer | app (SAZ) | python (`send()`) | verdict |
|---|---|---|---|
| request line | `POST https://app.adjust.com/session HTTP/1.1` (absolute-form via proxy) | `POST /session HTTP/1.1` (origin-form, direct) | equivalent on the wire |
| header set+order | Client-SDK, Authorization, Content-Type, User-Agent, Host, Connection, Accept-Encoding, Content-Length | **identical, same order** | byte-equal |
| Authorization format | `Signature signature="…",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"` | identical string (`adj9_full_chain.py:174-180`) | byte-equal |
| GET /attribution headers | Client-SDK, Authorization, User-Agent, Host, Connection, Accept-Encoding | identical | byte-equal |
| body encoding | quote_plus, 43/47/22 params, SAZ order | `urllib.parse.urlencode` (quote_plus), template order (`FC.S1P/S2P`) | byte-faithful (ARM C: 43/47/22 params, claims 360/391/246 B == device) |
| UA | `Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)` | same string (`FC.UA`) | byte-equal |
| **TLS ClientHello** | **Conscrypt (Android 12), TLS 1.3** (`1_m.xml`: `https-client-version=Tls13`) | **CPython OpenSSL (Windows)** — different cipher list, extensions, curves; no ALPN | **DIFFERENT** |
| **HTTP version** | h1.1 on the MITM leg (Fiddler can't do h2); direct leg almost certainly **h2** (Android's `HttpURLConnection` is OkHttp-based + Conscrypt ALPN) | **HTTP/1.1, no ALPN offered** | **DIFFERENT (unobserved, probable)** |
| TCP/IP | Android/Linux (TTL 64, Linux options) | Windows (TTL 128, Windows options) — p0f-visible | DIFFERENT (but eliminated, §3/§4) |

Value-level (A-candidate) diff inside params/claims: only fresh fields
(`gps_adid`, `android_uuid`, `created_at`/`sent_at`, `installed_at`) — all
plausible, self-consistent, and matched in the failing arms. Every other value
is byte-identical, including `adj_verification` (constant, offline-computed),
`adj_signing_id="1500000"`, cert SHA-1 `#9 = fad0f10d…` (= the app's real Play
cert, cross-confirmed by the genuine `X-Android-Cert` header in SAZ session
5), `environment=production`, `language=tr`, no `mcc`/`mnc`, no `idfa`
anywhere.

`send_device` note (TRANSPORT2's transport): `adb shell curl`
(`adj9_full_chain.py:183-225`) additionally reorders headers
(Client-SDK, **User-Agent, Authorization**, Content-Type) and adds curl's
default **`Accept: */*`** — an application-layer impurity the app never sends.
The PC `http.client` path has no such defect.

---

## 3. Click-record analysis (C)

| arm | GAID | click | session IP vs click IP | UA/geo consistency | outcome |
|---|---|---|---|---|---|
| ARM C (`mint_arm_c_result.json`) | `7d3125c7-…` (fresh) | synthetic PC curl click, 302, reftag `cPZq18SbbDQUu` issued | same PC egress (`106.219.162.119`) | consistent (moto g42 UA ↔ moto g42 profile, all +0530) | 200+adid, **Organic ×5 polls** |
| ARM D (`mint_arm_d_result.json`) | `8e39efb6-…` (pre-clicked) | real prior click, real reftag `cBY97SSI6u6Kx` delivered on sdk_click | click origin = "Pixel 7 Pro" profile (TR/Turkcell, +0200); session from the same Indian PC egress | **internally inconsistent** (TR tz/SIM/UA vs IN IP) | 200+adid, **Organic ×4 polls** |
| M4 win (9-14) | `d016e7e4-…` | real ad-network click ~2 h before install | device | consistent | **VKM non-organic** |
| g42 wins (9-24) | `f3f61a33-…`, `1adc8c94-…` (fresh GMS) | **synthetic device curl click** (same recipe as ARM C, `creative=cline_1p8t3`, 302) | device (click and session same IP) | consistent | **VKM non-organic** |
| TRANSPORT2 (9-24) | `f47c7f00-…` (fresh GMS) | **synthetic device curl click, identical recipe, minutes apart** | device | consistent | 200+adid, **Organic ×4 polls** |

(C) says the Python GAIDs had no qualifying click record. Refuted twice:

1. **TRANSPORT2 vs g42-win pairing**: identical click mechanism (adb curl on
   the same tracker URL from the same device, minutes apart, both 302 with
   reftags). The click record existed and was joinable — it joined for the
   app's session and not for ours (`arm_transport2_result.json` vs
   `TRANSPORT2_RESULT.md` §3). Click-record quality is therefore not the
   discriminator.
2. **ARM D** delivered a genuine reftag from a click that really happened —
   still Organic. Conversely ARM C was fully geo-consistent and still Organic,
   so ARM D's TR-vs-IN mismatch is not the sole gate either.

What the click record must be for a join: exactly what both 9-24 runs had — a
302-recorded tracker click bearing the same GAID, fired from the same egress
IP as the session. Python arms satisfied that too. **(C) is dead.**


---

## 4. Transport-arm audit

- **TRANSPORT2** (`arm_transport2.py` → `arm_transport2_result.json`): YES,
  attribution was polled for GAID `f47c7f00-a155-4cb1-8a90-d9ef0cde2753` — the
  saved JSON holds **4 polls, all `200 wy7261z / Organic /
  engagement_time=0001-01-01`, installed_at 2026-09-24T10:02:48Z** (the
  mission's "NO verdict" note reflects an earlier partial save; the final JSON
  has them). Session+sdk_click both 200, same adid
  `1b1e651e2cfbccad432af0d916be7095`. Transport: **`adb shell curl` on the
  device** — i.e., device IP and Android TCP stack, but **curl's own TLS
  client (BoringSSL build), not the app's Conscrypt**, plus the curl header
  impurities of §2. So TRANSPORT2 eliminated **IP, TCP fingerprint, geo,
  click mechanism, GMS-GAID provisioning, CTIT, params, and the F.py blob**
  — and left the TLS/HTTP client stack untouched as a variable.
- `arm_transport.py` (v1, 14:33) has no saved result JSON; superseded by v2.
- `oneclick_result.json` (15:34): dry-run artefacts + a session/sdk_click
  probe returning the null adid `0000…0000` with `ask_in:2000` — not an
  attribution datapoint.
- Historical corroboration that the client stack was never the controlled
  variable: `attempt10.py` tried to send via "okhttp4" impersonation and
  **fell back to raw OpenSSL** ("curl_cffi 0.16 has no okhttp target");
  `attempt11.py` did send /session via `curl_cffi impersonate=
  chrome131_android` (Android BoringSSL + h2) but against a **stale 6-day-old
  device record** (session_count=2, re-engagement shape) and read the old
  record's Organic — not a clean fresh-install test
  (`attempt11_console.log`).

---

## 5. Verdict — the discriminator

**(B), refined: the server-side check that splits app from Python is not in
the blob and not in the form params; it is the provenance of the connection
carrying the signed requests — concretely the TLS client fingerprint
(Conscrypt/Android vs OpenSSL/curl) and, most likely bundled with it, the
HTTP-stack fingerprint (ALPN-negotiated h2 + OkHttp framing).**

Why not (A) — claim values inside descriptor #10:

- Every server-independently-verifiable claim value was matched in arms that
  still failed: `gps_adid` vs the click DB (ARM C, TRANSPORT2: fresh GAID,
  click fired with it, 302 + reftag), created/sent/installed timing
  consistency (real 217.431 s CTIT), `session_count=1` on a fresh GAID,
  cert #9 (real Play cert SHA-1, `fad0f10d…`), `adj_verification` (constant),
  `environment=production`, device profile consistent with click UA
  (TRANSPORT2). `PARAM_DIFF.md` + `ARM_C_RESULT.md`: 43/47/22 params,
  360/391/246-B claim strings — byte-faithful.
- Structurally, the server **cannot** read the claims out of our blob either
  way: the 176-B body is a lossy fold of ~460 B of descriptors seeded by
  per-call entropy (`V = tv_sec ^ tv_usec`, pid) that is never transmitted
  (`WALL_A_SLICE_147.md`, `mint_pipeline.py` header). The only
  server-checkable blob property is the 16-B header law
  (`make_header(second)`), which our mint satisfies. Slice 82's taint probe
  found **0/44 body dwords server-verifiable** for acceptance
  (`STATUS.md`); the F_FIX run proved even a device-faithful, L3-passing
  region changes nothing (`F_FIX_RESULT.md`).
- The Keystore HMAC (`key2`, TEE) is passed to `nSign` but provably does not
  influence the wire bytes — our mint takes no HMAC yet reproduces device
  blobs byte-exact (14/14 + 8/8). The server never learns `key2` (ORIGIN=0,
  never uploaded — `ADJ9_VALIDATION_MODEL.md` §1), so no MAC check is
  possible server-side.

Why not (C): §3 — the identical synthetic device-curl click joined when the
app sent the session (both 9-24 g42 wins) and did not join when Python sent
it (TRANSPORT2), minutes apart, same device, same tracker URL.

What (B) means precisely: Adjust's backend fails open for untrusted clients —
it **accepts** any well-formed signed request (`200 + adid`, so spoofers get
no signal) but only **joins attribution** for installs whose report arrives
over a client stack consistent with the genuine SDK (Android
Conscrypt/OkHttp-family TLS fingerprint + h2). The `wy7261z`/"Organic"
fallback with the correct `installed_at` (slice 143 measurement 1) is exactly
that fail-open behavior. Every winning stream in the entire corpus came from
the app's own Conscrypt stack (M2/M3/M4 on-device, 9-15 win_attempt ×3, 9-21
OnePlus, 9-24 g42 ×2); every losing stream came from OpenSSL (PC),
AOSP-curl/BoringSSL (device curl), Chrome-Android-BoringSSL (attempt11), or
today's near-Conscrypt+OkHttp-h2 approximation (§6).
The split is perfectly explained by the TLS/HTTP client; no other variable
survives.

Residual honesty: the app's **exact** direct-path ClientHello has never been
captured (all captures are MITM'd legs; Fiddler records only
`https-client-version=Tls13`). "Conscrypt fingerprint" is therefore an
inference from elimination, not a byte-read of the gate. The experiment below
is how to convert it into a proof.


---

## 6. The decisive experiment

**The single most decisive experiment (decisive in BOTH directions): send OUR
Python-minted bytes through the real app's own TLS/HTTP stack on the device.**

Recipe (needs the device, currently disconnected): repeat TRANSPORT2 (fresh
GMS GAID + device curl click + real CTIT), but instead of curl-transport,
hook the running app's Adjust request path (Frida/LSPosed — the workspace
already has the nSign oracle module in `adj9/module/`) and substitute the
`/session` + `/sdk_click` bodies and `Authorization` headers with our
minted bytes as they leave the app. The app's Conscrypt stack, ALPN, h2
framing, timing and process provenance all stay genuine; only the payload
bytes are ours (and they are byte-faithful anyway).

- If the click **joins** → our content pipeline is complete; the gate is
  purely the client-stack fingerprint, and a PC-side fix (exact Conscrypt
  hello + OkHttp h2) becomes a matter of fingerprint engineering.
- If it stays **Organic** → the gate depends on something even deeper than
  the TLS stack (e.g. per-connection behaviour impossible to forge
  off-stack); either way the current ambiguity is resolved.

**PC-side approximation run today**: `rev/arm_tls_cffi.py` — three parallel
arms, ARM-C recipe held constant (fresh GAID, PC tracker click 302, real
217.431 s CTIT, F.py-minted blobs, moto g42 profile), only the transport
client of the three signed calls varied:

| arm | client | preflight (tls.peet.ws) |
|---|---|---|
| `openssl` (control) | CPython http.client, OpenSSL, h1.1, no ALPN | (established failing shape) |
| `chrome_android` | curl_cffi `impersonate=chrome131_android` | JA3 `…4865-4866-4867-49195-49199-49196-49200-52393-52392…`, h2 (GREASE-permuted), peetprint logged |
| `conscrypt` | curl_cffi custom JA3 + OkHttp akamai `4:16777216\|16711680\|0\|m,p,a,s` | JA3 `771,4866-4867-4865-49196-49200-49195-49199-52393-52392-159-158-4865-49188-…,0-23-65281-10-11-35-16-51-43-13-45-21,29-23-24-25-256-257,0` (hash `8783ea04…`), h2 |

(Note: 52394/0xCCAA and the 493xx CCM-8 block were dropped from the published
Conscrypt cipher list because curl_cffi's cipher map doesn't know them — the
`conscrypt` arm is therefore best-effort, not byte-exact Conscrypt. Server
capability check 2026-09-24: `app.adjust.com` answers h1.1/h2/h3; a bare GET
`/` → 404 over h3 with the chrome profile, 404 over h1.1 with http.client.)

**Result** (`rev/arm_tls_cffi_result.json`, `rev/arm_tls_cffi.log`,
2026-09-24 ~10:42–10:56 UTC, live):

| arm | GAID | reftag | /session | /sdk_click | /attribution ×3 |
|---|---|---|---|---|---|
| `openssl` | `b97793e5-…` | `cOPl2KR6oU6Kn` | 200, adid `7d62a9a6…` | 200, same adid | `wy7261z / Organic / eng=0001-01-01` ×3 |
| `chrome_android` | `fa461bfe-…` | `cuSoqE0WcSNGg` | 200, adid issued | 200, same adid | `wy7261z / Organic / eng=0001-01-01` ×3 |
| `conscrypt` | `ac8d3fcc-…` | `cp7wa70uRA33i` | 200, adid issued | 200, same adid | `wy7261z / Organic / eng=0001-01-01` ×3 |

All three signed calls in all three arms were accepted (200 + one adid per
identity); all nine attribution polls returned the Organic fallback. **No
transport-fingerprint arm joined.** The `conscrypt` arm negotiated h2 with
the exact OkHttp akamai string (`4:16777216|16711680|0|m,p,a,s`) and a
near-Conscrypt JA3 (`8783ea04…`); the `chrome_android` arm presented the
genuine Chrome-Android BoringSSL fingerprint. Both failed exactly like
OpenSSL.

What this run establishes:

- The gate is **not** satisfied by "any Android-family BoringSSL
  fingerprint" or by OkHttp's exact h2 settings over a near-Conscrypt hello.
  If the gate is the client stack at all, it demands the **byte-exact**
  genuine Conscrypt ClientHello (the approximation lacked the 0xCCAA and
  CCM-8 codepoints and possibly extensions 5/28 — enough to miss), plus
  whatever else the real stack does.
- The cheap PC-side fix is therefore dead; the device-side injection
  experiment above is promoted from "decisive" to **mandatory** for a
  byte-level proof. (This negative result does NOT re-open (A) or (C): both
  remain refuted by their own controls — §3's same-mechanism pairing and
  §5's claim-by-claim exhaustion are unaffected.)


---

## 7. Artifacts & live-request log

New artifacts from this investigation:

- `rev/SIGGATE_INVESTIGATION.md` — this report.
- `rev/arm_tls_cffi.py` — the 3-arm transport-fingerprint experiment.
- `rev/arm_tls_cffi_result.json` — full request/response log + verdicts.
- `rev/arm_tls_cffi.log` / `rev/arm_tls_cffi_err.log` — console transcripts.
- `rev/_saz_x/` — freshly extracted `penti_android_test.saz` (raw client/
  server/metadata files) used for §1–§2 byte comparisons.

Live requests made from this PC on 2026-09-24 (all logged in
`arm_tls_cffi_result.json.request_log` unless noted):

1. `GET tls.peet.ws/api/all` ×4 — fingerprint preflight for the two cffi
   arms (2 during tuning, 2 in the final run).
2. `GET app.adjust.com/` ×2 — server ALPN capability check (h3 via chrome
   profile; h1.1 via http.client; both 404). Logged in this report §6 only.
3. `GET app.adjust.com/1sd1lk6a?…` ×3 — tracker clicks for GAIDs
   `b97793e5-…`, `fa461bfe-…`, `ac8d3fcc-…` (302 + reftags
   `cOPl2KR6oU6Kn` / `cuSoqE0WcSNGg` / `cp7wa70uRA33i`).
4. `POST app.adjust.com/session` ×3, `POST app.adjust.com/sdk_click` ×3,
   `GET app.adjust.com/attribution` ×9 — the experiment arms (all 200).

Key prior artifacts relied on: `rev/_saz_x/raw/{1,2,3}_{c,s}.txt` + `*_m.xml`
(winning-request anatomy + `x-processinfo` provenance), `rev/saz_params.json`,
`rev/corrected_claims.json`, `rev/PARAM_DIFF.md`, `rev/ARM_C_RESULT.md` +
`mint_arm_c_result.json`, `rev/ARM_D_RESULT.md` + `mint_arm_d_result.json`,
`rev/TRANSPORT2_RESULT.md` + `arm_transport2_result.json`,
`rev/G42_WIN_RESULT.md`, `rev/F_FIX_RESULT.md`, `rev/WALL_A_SLICE_143.md`,
`rev/pixel7_click.json`, `device/fresh_click_install_g42.py`,
`rev/arm_transport2.py`, `rev/mint_pipeline.py`,
`rev/adj9_full_chain.py:174-299`, `rev/attempt11.py` +
`attempt11_console.log`, `rev/win_attempt_result.json`,
`rev/java_signer.md` §6, `rev/ADJ9_VALIDATION_MODEL.md` §1.

