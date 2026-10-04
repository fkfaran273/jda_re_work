# HTTP/TLS Fingerprint Diff — com.penti.app (OkHttp on device) vs our Python client

Date: 2026-09-27. Device: moto g42 (ZD2228MY3X, Android 12, API 31), app 3.14.x,
`Client-SDK: android5.7.0`. Question: with the SAME claims and the SAME adj9
blob, the app's `/session` books NON-ORGANIC and our Python `/session` books
ORGANIC — everything below is the transport-level difference between the two.

## 0. How this was captured (no MITM, no frida, device untouched)

The LSPosed `sslunpinning` module was **not** re-enabled and no frida touched
the app (rules respected; the device stays "oracle module only"). Fiddler-style
TLS interception was impossible anyway: the system CA store is stock (131
certs) and the app does not trust user CAs.

Instead: a **passthrough CONNECT proxy** (`tunnel_cap/passthrough_proxy.py`,
PC `192.168.0.104:8889`, no TLS termination — it relays bytes verbatim and logs
them). The device proxy was pointed at it (`settings put global http_proxy`),
the app was wiped (`pm clear com.penti.app`) + relaunched via monkey, and the
full first-open Adjust flow passed through the tunnel with its **real TLS
handshake visible byte-for-byte**. `tcpdump` ran on the device in parallel for
per-record wire timestamps. Afterwards the Python arm (`adj9_api.Api.session`,
urllib/http.client) was sent through the same proxy the same way, with
`http.client.HTTPConnection.send` patched to dump its exact wire bytes.

Artifacts (all under `adj9/rev/tunnel_cap/`):
- `passthrough_proxy.py`, `tls_parse.py`, `pcap_time.py`, `capture_python_send.py`
- `master.jsonl` — every CONNECT event; `1790532046_11_*` = app tunnel, `1790533151_55_*` = python tunnel
- `1790532046_11_app.adjust.com_443_{connect.txt,c2s.bin,s2c.bin}` — app's CONNECT headers + raw TLS stream
- `1790533151_55_app.adjust.com_443_{c2s.bin,s2c.bin}` — python's raw TLS stream
- `python_wire_send.bin` — python's exact request bytes (header block + body)
- `cap_fp.pcap` — device tcpdump (final pull includes both arms)
- App reference for plaintext headers/bodies: the external Fiddler SAZ from the
  second device (`C:\Users\Apps\Downloads\pentindroid_logs_saz\raw\{1..4}_c.txt`,
  documented in `SAZ_LIVE_TRAFFIC.md`) — app 3.12.1 / Oneplus DN2101 / API 30.

## 1. The app's exact `/session` request (what we must reproduce)

Header block exactly as the app puts it on the wire (order and casing from the
SAZ capture, which stores the decrypted request verbatim; same order confirmed
semantically by the app's own CONNECT block this run):

```
POST /session HTTP/1.1              (origin-form inside the CONNECT tunnel)
Client-SDK: android5.7.0
Authorization: Signature signature="<256 base64 chars>",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
Content-Type: application/x-www-form-urlencoded
User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)
Host: app.adjust.com
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: <n>
```

Order: **Client-SDK, Authorization, Content-Type, User-Agent, Host,
Connection, Accept-Encoding, Content-Length**. That is OkHttp's canonical
write order: the SDK's two headers first, then `Content-Type` (from the
FormBody) and `User-Agent` (client default), then BridgeInterceptor's
`Host`/`Connection: Keep-Alive`/`Accept-Encoding: gzip`, and `Content-Length`
last. The same 8-header block is used on all endpoints (`2_c.txt` /sdk_click,
`3_c.txt` /sdk_info identical; `4_c.txt` /attribution GET drops
Content-Type/Content-Length). Header *values* are mixed-case as shown —
`Client-SDK` has **capital SDK**.

Proxy layer — the app's CONNECT (captured this run, `..._connect.txt`):

```
CONNECT app.adjust.com:443 HTTP/1.1
Host: app.adjust.com:443
Proxy-Connection: Keep-Alive
User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)
```

## 2. Our Python request, byte-for-byte (from `python_wire_send.bin`)

```
POST /session HTTP/1.1
Accept-Encoding: identity
Content-Length: 1027
Host: app.adjust.com
Client-Sdk: android5.7.0
User-Agent: Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)
Authorization: Signature signature="...",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
Content-Type: application/x-www-form-urlencoded
Connection: close
```

Proxy layer — python's CONNECT:

```
CONNECT app.adjust.com:443 HTTP/1.1
Host: app.adjust.com:443
```

(no `Proxy-Connection`, no `User-Agent` — a bare urllib CONNECT.)

## 3. Header diff — the answers to "missing / casing / order / extra"

**No header is missing and none is extra — the SET is the same 8.** The
differences are casing, order, and two values:

| # | App (OkHttp) | Python (urllib) | diff |
|---|---|---|---|
| 1 | `Client-SDK: android5.7.0` | `Client-Sdk: android5.7.0` | **casing** (urllib `key.capitalize()` mangles it) |
| 2 | `Authorization: Signature …` (2nd) | (6th) | **order** |
| 3 | `Content-Type: application/x-www-form-urlencoded` (3rd) | (7th) | **order** |
| 4 | `User-Agent: Dalvik/2.1.0 (…)` | same value | order only |
| 5 | `Host: app.adjust.com` | same value | order only |
| 6 | `Connection: Keep-Alive` | `Connection: close` | **value** |
| 7 | `Accept-Encoding: gzip` | `Accept-Encoding: identity` | **value** |
| 8 | `Content-Length` (last) | (2nd, right after request line) | **order** |

Both sides advertise `HTTP/1.1`, and the header block totals happen to be the
same size (~691 B) — only the arrangement differs.

## 4. URL/body encoding diff

- **Space encoding: `+` vs `%20`.** Python `urllib.parse.urlencode` emits
  `device_name=moto+g42`. OkHttp's FormBody percent-encodes, i.e. the app sends
  `device_name=moto%20g42`. (The SAZ reference body has no space-bearing value
  to prove it byte-for-byte — the OnePlus device name was `DN2101` — but
  OkHttp's FormBody canonicalizer is `%20`; flagged as high-confidence
  inference.) Everything else (colons `%3A`, offset `%2B0530`) matches.
- **Body key ORDER differs.** The app's real `/session` body (SAZ, app 3.12.1)
  interleaves device fields early:
  `store_name_from_system, gps_adid_attempt, api_level, hardware_name,
  app_version, app_token, installed_at, created_at, wait_total, device_type,
  language, gps_adid, …` — while our template emits core params first and
  appends all `_dev_fields` at the end
  (`…, tracking_enabled, api_level, os_version, device_name, …,
  created_at, sent_at, installed_at, updated_at`). Caveat: the SAZ is app
  3.12.1; `AGENT_reqdiff.md` §2 proved order-parity only for the
  oracle-signed *driver maps*, not the app's genuine wire — for the current
  app this is re-checkable only via a trusted-CA MITM, which this setup
  deliberately avoids.
- Timezone label `+0530` in our body is correct for the device as of today
  (`persist.sys.timezone = Asia/Kolkata` — checked, not stale).
- No SIM on the g42: neither side sends `mcc`/`mnc` (the SAZ device did —
  device property, not a fingerprint element).

## 5. TLS ClientHello — the biggest fingerprint gap

Both parsed from the raw tunnel bytes (`tls_parse.py`); full listings in the
capture dir. Headline numbers:

| element | App (Conscrypt/BoringSSL, Android 12) | Python (OpenSSL 3.14) |
|---|---|---|
| ClientHello size | **517 B record (512 handshake)**, padded via `padding(21)` ext (238 B) to 512 | **1540 B record (1535)**, no padding — inflated by a post-quantum key share |
| cipher suites (order) | 17: `1301,1302,1303` (AES128 first), ECDSA-before-RSA ECDHE, `cca9,c02f,c030,cca8`, CBC-SHA tail `c009,c00a,c013,c014`, RSA-PSK `009c,009d`, `002f,0035` | 17: `1302,1303,1301` (AES256 first), RSA-before-ECDSA for GCM, includes DHE `009f,009e,006b,0067`, no RSA-PSK, no CBC-SHA tail |
| supported_groups | **3**: `x25519, secp256r1, secp384r1` | **8**: `x25519_ml_kem768(0x11ec) first!, x25519, secp256r1, x448, secp384r1, secp521r1, ffdhe2048, ffdhe3072` |
| key_share | `x25519` only (32 B) | `x25519_ml_kem768` (**1216 B**) + `x25519` |
| extensions (order) | `server_name, extended_master_secret, renegotiation_info, supported_groups, ec_point_formats, session_ticket(35), alpn, status_request, signature_algorithms, key_share, psk_key_exchange_modes, supported_versions, padding` | `renegotiation_info FIRST, server_name, ec_point_formats, supported_groups, session_ticket(35), alpn, encrypt_then_mac, extended_master_secret, post_handshake_auth, signature_algorithms, supported_versions, psk_key_exchange_modes, key_share` |
| signature_algorithms | 9: `0403,0804,0401,0503,0805,0501,0806,0601,0201` | 26: adds ML-DSA `0905,0906,0904` and full X25519/Ed set |
| ec_point_formats | `uncompressed` only | `uncompressed, ansiX962, prime_primefield` |
| `status_request` (OCSP) | **present** | absent |
| `post_handshake_auth` | absent | present |
| GREASE | none (Conscrypt disables it) | none |
| ALPN offer | **`http/1.1` only** | `http/1.1` only (same) |
| supported_versions | `TLS1.3, TLS1.2` | same |

Negotiated result is the SAME on both (TLS 1.3, `TLS_AES_256_GCM_SHA384`,
x25519 — server preference), so the *negotiated* parameters don't separate the
arms; **the offer does**. Any server-side TLS fingerprint (JA3/JA4-style:
ciphers+extensions+groups+sigalgs in order, or simply "ClientHello is 517 B
padded Conscrypt vs 1540 B ML-KEM OpenSSL") separates them maximally.

## 6. Protocol level, connections, ordering (task questions)

- **HTTP/2? NO.** The app's ClientHello offers ALPN `http/1.1` only (its OkHttp
  is configured HTTP/1.1-only), so every request is HTTP/1.1. (The server does
  support h2 — an openssl probe offering `h2,http/1.1` negotiated h2 — the app
  just never offers it.)
- **New connection or reuse?** ONE connection for the whole flow: a single
  `CONNECT app.adjust.com:443` at first launch, and `/session`, `/sdk_click`,
  `/attribution` all run over that one TLS tunnel (keep-alive). The server
  closes it ~5.2 s after the last response (`close_notify` + FIN from the
  server side; the app had kept it idle-pooled).
- **Session immediately or after other requests?** `/session` is the **first**
  request, on the wire ~0.2 s after the tunnel opens (device app-start →
  CONNECT → ClientHello → session in one burst). `/sdk_click` follows +0.8 s,
  `/attribution` +0.9 s after that. `/sdk_info` did **not** appear at all in
  this fresh-install run; in the SAZ reference it also came *after*
  `/session` (never before). So the app's ordering matches our driver's
  session → click → attribution; `sdk_info` is not a preceding request.
- Timeline of the app tunnel (pcap timestamps, `pcap_time.py`):
  `+0.00 CONNECT` → `+0.37 ClientHello(517B)` → `+0.59 server flight` →
  `+0.60 CCS+Finished` → `+0.60 /session (1740B record)` → `+1.18 resp(351B)` →
  `+1.40 /sdk_click (1742B)` → `+1.90 resp(351B)` → `+2.24 /attribution (1178B)`
  → `+2.51 resp(616B)` → `+7.53 server close`.

## 7. What to change in the Python client (ranked)

1. **TLS ClientHello**: cannot be fixed with python `ssl`. Build a
   uTLS/`ClientHelloSpec` (Go) or curl-impersonate-style relay from the
   captured app values: 512-byte padded Conscrypt hello, the 17-cipher list in
   the app's order, 3 groups (`x25519, secp256r1, secp384r1`), x25519-only
   key share, the 13 extensions in the app's order (incl. `status_request`,
   excl. `post_handshake_auth`/ML-KEM), 9 sig algs, ALPN `http/1.1` only.
2. **Header casing**: send `Client-SDK` (capital SDK) — bypass urllib's
   `capitalize()` (e.g. build the request with raw `http.client` and
   `putheader("Client-SDK", …)` directly).
3. **Header order**: emit exactly `Client-SDK, Authorization, Content-Type,
   User-Agent, Host, Connection, Accept-Encoding, Content-Length`
   (`putrequest(..., skip_accept_encoding=True, skip_host=True)`, then the
   eight `putheader` calls in that order).
4. **Header values**: `Connection: Keep-Alive` (not `close`) and
   `Accept-Encoding: gzip` (not `identity`).
5. **Space encoding**: percent-encode (`%20`), i.e. `quote()` not
   `quote_plus()` semantics, OkHttp-FormBody-style.
6. **Reuse one keep-alive connection** for session → click → attribution
   (http.client `HTTPSConnection` reused, h1.1).
7. Match the CONNECT block if a proxy is on path: `Proxy-Connection:
   Keep-Alive` + the Dalvik `User-Agent`.

Items 2–6 are free; item 1 is the expensive one and the most distinctive
(517-byte padded Conscrypt hello vs a 1540-byte ML-KEM OpenSSL hello).

## 8. Caveats

- The app's plaintext header block comes from the external SAZ (app 3.12.1 on
  the OnePlus). Header casing/order is SDK-level (OkHttp + android5.7.0) and
  the current app's CONNECT block this run is OkHttp-identical, so the carry-
  over is sound; the body key-order caveat in §4 stands.
- This run's app requests were not decrypted (by design — no CA trust, no
  hooks). Request identities were established by wire-size matching against
  the SAZ bodies (session 1723 B ≈ 691 header block + 1027 B template body;
  responses 351/351/616 B match the SAZ click/attribution response sizes and
  the `{"app_token","adid"}` shape) and by the pcap per-record timeline.
- The 159 B packet at +2.31 s in the pcap is a partial TCP retransmission of
  the /attribution request, not a fourth request (seq-inside range).
- State left clean: device proxy restored to `:0`, tcpdump stopped, no frida,
  LSPosed module list untouched (oracle only).
