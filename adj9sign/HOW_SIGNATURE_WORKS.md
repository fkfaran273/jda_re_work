# How the adj9 signature is made — a plain-language tour

This explains what `adj9_signer.py` does, part by part, so you can read the
code and explain it to someone else. No reverse-engineering background needed.

---

## 1. The big picture

Every API request (`/session`, `/sdk_click`, `/attribution`) carries an
`Authorization` header that looks like this:

```
Authorization: Signature signature="BASE64___192_BYTES",
               adj_signing_id="1500000",
               algorithm="adj9",
               headers_id="10",
               native_version="5.0.0",
               adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
Client-SDK: android5.7.0        <- separate header, also mandatory
```

The `signature="..."` part is the actual signature: **192 bytes**, base64
encoded. Think of it as a sealed envelope:

```
 +--------------------------------------------------------------+
 |  16-byte HEADER   |          176-byte BODY (encrypted)       |
 |  "the postmark"   |            "the letter"                  |
 +--------------------------------------------------------------+
        1 second of work        the real content lives here
```

- The **header** is derived only from the clock — it tells the server *when*
  the signature was made.
- The **body** is encrypted and contains everything the server wants to
  verify: which app, which device, what request, and device-generated
  randomness.

Both parts are produced by one run of the app's native signing machine.

---

## 2. The 16-byte header — "the postmark"

Made like this (function `make_header` in `adj9_signer.py`):

1. Take the current time **in whole seconds** (`time.time()`).
2. Feed it as a seed into the exact random-number generator Android uses
   (`srand(time)` then 8 draws of `rand()` — we reimplemented bionic's `rand`).
3. XOR the 8 draws in pairs → 4 numbers of 4 bytes each = **16 bytes**.

It looks random, but it is fully determined by the second. Consequence:
**anyone who knows the signing second can recompute the header**, and the
server can read the signing time out of it. That is why our mint uses the
real current second — a wrong clock = a wrong header = instant rejection.

---

## 3. The 176-byte body — "the letter", decrypted

The body is encrypted with a custom 14-round cipher (S-box + byte shuffle +
linear mixing — all extracted and reversed). We can decrypt any body with
`whiten_body_inverse`. Decrypted, it is a **144-byte record** laid out like:

| bytes | content | what it is |
|---|---|---|
| 0–2 | `01 00 08` | magic marker, always the same |
| 3–18 | **d0 head** | first bytes of the device-made random region |
| 20–23 | **S** | a fresh 4-byte random seed (`/dev/urandom`) |
| 25–44 | **cert SHA-1** | fingerprint of the app's signing certificate |
| 46–77 | 32-byte block | a byte-copy of other data already in the record |
| 79–110 | `SHA256("")` | constant checksum — proves decryption succeeded |
| 114–127 | zeros | padding |
| 130–143 | `0e` × 14 | fixed tail pattern |

Two parts matter most:

- **cert SHA-1** — this is the app's identity. It comes from the real APK's
  signing certificate, so the server knows the signature was made by (or with
  the knowledge of) the genuine app binary.
- **S + the region** — fresh device-made randomness for *this* signing.

### The region (d0, d2, d4)

From the 4-byte seed S, the app materializes three buffers using a
Park-Miller PRNG, a shuffle, and a bit-mixing step called the "whitener":

- **d0** — 36 words. Its first few words come from special "selector" calls;
  the genuine device uses the pattern `(0x2B, 0x48)` then a repeating cycle.
  That pattern is baked into our signer (`WIN_HEAD`).
- **d2** — just S stored little-endian (a way for the record to carry the seed).
- **d4** — 8 words, more seed-driven material.

This is the part that used to require the device. We reverse-engineered the
materializer completely (functions `region`, `_d4_words`, `_d0_words`), so now
Python produces it from any seed.

---

## 4. The claims — "the form you are signing"

The single biggest piece of the signature is the **claims string**
(descriptor #10): the request's own parameters, serialized in a fixed key
order. This is what makes the signature *bound to the request*:

```
session claims (360 B):  app_token, app_version, gps_adid, android_uuid,
                         created_at, device_name, os_version, ...
click claims  (388 B):   same profile keys + referrer, click_time,
                         referrer_api, google_play_instant, ...
attribution claims (242 B): profile keys + initiated_by, tracking_enabled
```

The key order is a law we proved byte-exactly against the device: profile
keys A→Z, then `adj_signing_id`, then the tail keys, then
`activity_kind, client_sdk, headers_id, native_version`.

**This is why every request must be signed separately.** The server takes the
received parameters, rebuilds the expected claims string, and compares it with
what is inside the signature. Reuse the session's signature on the click
request → the claims don't match → the click fails. (That exact bug cost us
weeks: it is the difference between a 500 and a 200.)

---

## 5. The signing machine (FinEx) — where it all gets mixed

The app's native library (`libsigner.so`) is an obfuscated **virtual machine**:
a tiny ARM64 computer inside the app that consumes "descriptors" and emits the
signature. We lifted its bytecode out of the library and wrote a Python
interpreter for it — that is the big `FinEx` class (~10 million VM steps per
signature, 15–60 s).

It receives the inputs as an ordered list of **descriptors**:

| # | content | source |
|---|---|---|
| 0 | d0 (36 words) | region — from seed S |
| 9 | fixed constant | extracted from the app |
| 8 | fixed constant | extracted from the app |
| 4 | d4 (8 words) | region — from seed S |
| 2 | d2 (S) | the seed |
| 7 | unpadded claims length | from the claims |
| 10 | the claims string | from the request parameters |
| 5, 6 | zeros | fixed |
| 1, 3 | empty | fixed |

and it emits **one stream of 48 words**: the first 4 words are the 16-byte
header, the next 44 words are the encrypted 176-byte body. The header law and
the encryption both happen inside the VM — that is why the mint result is
already the complete 192-byte signature.

The 32-byte block inside the record? Traced to the last byte: it is simply a
**copy of data the VM had already written earlier in the stream** — no extra
input, no secret. Every byte of the signature is now accounted for.

---

## 6. The whole flow in one page

```
 python run_funnel.py
        |
        |-- 1. CLICK: open the tracker link with a browser fingerprint
        |        -> get a reftag + referrer string
        |
        |-- 2. /session:   params = device data + fresh timestamps
        |        sign(params, kind="session")
        |
        |-- 3. /sdk_click: params = click canonical + referrer
        |        sign(params, kind="click")
        |
        '-- 4. /attribution: params = identity + poll options
                 sign(params, kind="attribution")

 sign(params, kind):
    claims = serialize(params)            # fixed key law, per kind
    S      = 4 random bytes               # fresh per signing
    d0,d2,d4 = materialize(S)             # the reversed region machine
    descs  = [d0, consts, d4, d2, len, claims, zeros...]
    blob   = FinEx(seed = current second).emit(descs)   # 192 bytes
    return "Signature signature=<blob>,adj_signing_id=..."
```

## 7. What the server actually checks (and what we learned)

| check | how we satisfy it |
|---|---|
| header matches a plausible signing time | use the real clock second |
| body decrypts (checksum passes) | the VM's cipher is reproduced exactly |
| certificate SHA-1 | copied from the genuine app |
| claims == request parameters | sign EVERY request separately, per-kind law |
| region is internally consistent | the materializer is fully reversed |
| device is known to the tracker | use a **real GAID** (harvested once from a device) |
| not too frequent | 20 min minimum between sessions per device |

Everything inside the signature is pure computation — Python does all of it.
The only input that cannot be computed is the **GAID**: the tracker only
(re)attributes devices it already knows, so the one string must come from a
real device. That is why a random uuid gets `Organic` and a real GAID gets
booked (`is_reattributed: true`).

---

## 8. Where each piece lives in the code

| concept | in `adj9_signer.py` |
|---|---|
| header (postmark) | `make_header`, `Random3` |
| region from seed S | `region`, `_d4_words`, `_d0_words`, `_selector_halfword` |
| genuine head phase | `WIN_HEAD = (0x2B, 0x48)` in `run_funnel.py` |
| claims law | `desc10_keys`, `build_desc10`, `claims_for_law` |
| the VM | `FinEx` (and `Ex`, `FinStream` under it) |
| assembling + minting | `VA_ORDER`, `finex_mint`, `auth_header` |
| the runner | `run_funnel.py` (`sign`, `click`, `api`, `main`) |
