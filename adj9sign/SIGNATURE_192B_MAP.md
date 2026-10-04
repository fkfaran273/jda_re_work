# The adj9 signature — EVERY part explained

Two layers carry the signature: the **Authorization header text** (7 fields)
and the **192-byte blob** hidden inside the first field. Both are explained
here, part by part.

---

## Part A — the Authorization header, field by field

```
Authorization: Signature signature="...192B blob...",
               adj_signing_id="1500000",
               algorithm="adj9",
               headers_id="10",
               native_version="5.0.0",
               adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
Client-SDK: android5.7.0
```

| field | what it is | plain meaning |
|---|---|---|
| `Signature signature=` | the 192-byte blob, base64 | the actual cryptographic envelope — see Part B |
| `adj_signing_id="1500000"` | signing key id | *which signing key the app claims to use.* Fixed value of the production app. Also embedded inside the signed claims, so the server can check the header wasn't tampered with. It even selects which region flavor the signer produces. |
| `algorithm="adj9"` | scheme name | "signature format 9" — tells the server how to parse/verify the blob |
| `headers_id="10"` | layout version | *which claim/header format version was used.* Also inside the signed claims. |
| `native_version="5.0.0"` | signer library version | version of the native signing library (`libsigner.so`) that made the blob. Also inside the signed claims. |
| `adj_verification="KlcA…DHMI"` | verification token (24 chars, constant) | *the app's "I am the official SDK build" token.* A fixed string baked into this app's SDK — same on every device, every request. Copied verbatim from the app. It also goes INSIDE the signed claims, so the server cross-checks header ↔ claims. |
| `Client-SDK: android5.7.0` (separate header) | SDK version string | identifies the Adjust SDK. **Mandatory** — forget this header and the server answers `400 "unsupported sdk"` before even looking at the signature. |

**Key trick:** `adj_signing_id`, `headers_id`, `native_version`,
`adj_verification` (and `activity_kind`, `client_sdk`) appear BOTH in the
header text AND inside the signed claims. The signature covers them — so the
server knows the header fields themselves weren't swapped by a man-in-the-middle.

---

## Part B — the 192-byte blob, part by part

Your intuition is correct: **the first part is the timestamp part.**

```
 offset   0        16                       160        192
          +--------+------------------------+----------+
          |   1.   |          2.            |    3.    |
          | TIME   |   APP+DEVICE RECORD    |  DIGEST  |
          | 16 B   |  144 B (encrypted)     |   32 B   |
          +--------+------------------------+----------+
          plaintext      encrypted (9 chunks)    plaintext
```

### 1. TIME — bytes 0..16 (the timestamp part)

*What it is:* the signing second, encoded — not stored raw. The app seeds
Android's random generator with the current second (`srand(time)`), draws 8
numbers, XORs them in pairs → 4 words = 16 bytes.

*Why it's there:* proves **freshness** (when it was signed) without carrying
a readable timestamp. Same second → same 16 bytes, so the server can
recompute it, and old/replayed signatures stick out. It also doubles as the
encryption key (IV) for part 2.

### 2. APP+DEVICE RECORD — bytes 16..160 (encrypted, 144 B)

Decrypted, it is a small tagged list. Every field, in order:

| offset | bytes | field | what it tells the server |
|---|---|---|---|
| 0 | 3 | `01 00 08` magic | "this is a valid adj9 record" |
| 3 | 16 | **d0 head** | device-made region material — first words, produced with the genuine selector pattern (`2B 48 …`) |
| 19 | 1 | tag `02` | section marker |
| 20 | 4 | **S** (the seed) | a fresh 4-byte random number drawn at signing time — the seed that generated all the region material. Makes every signature unique even for identical requests. |
| 24 | 1 | tag `03` | section marker |
| 25 | 20 | **cert SHA-1** | fingerprint of the app's signing certificate — *proof the signature was made with the genuine, unmodified app binary* |
| 45 | 1 | tag `04` | section marker |
| 46 | 32 | **block** | a copy of earlier VM output words — this is where the **request's parameters (claims) leave their fingerprint** after being mixed by the signing machine. Change one request param without re-signing → these bytes no longer match. |
| 78 | 1 | tag `05` | section marker |
| 79 | 32 | `SHA256("")` | a constant checksum — proves the decryption succeeded (integrity check) |
| 111 | 3 | tag `06 01 07` | section marker |
| 114 | 14 | zeros | reserved / padding |
| 128 | 2 | `00 00` | padding |
| 130 | 14 | `0e` × 14 | fixed tail pattern |

### 3. DIGEST — bytes 160..192

*What it is:* 32 bytes produced by separate machinery inside the signing VM,
over everything above.

*Why it's there:* the final integrity seal — a last mixing of all the
material. Not encrypted, but unreadable without running the same VM.

---

## Part C — where the request parameters went (the claims)

The request's own data (app_token, gps_adid, created_at, referrer, …) is
serialized in a fixed key order into the **claims string** (360 B for a
session, 388 B for a click, 242 B for an attribution) and fed into the
signing VM as an input. It never appears verbatim — the VM **mixes** it into
the block and the digest.

That mixing is the **binding**: the server takes the parameters it received,
rebuilds the claims the same way, and checks the signature is consistent
with them. This is why:

- every request needs its **own** signature (a session signature on a click
  request = mismatch = error),
- editing any parameter after signing breaks the signature.

---

## Part D — one-line summary of each ingredient

| ingredient | source |
|---|---|
| TIME (16 B) | the clock (`srand(second)` → rand → XOR) |
| region d0 / d4 | device materializer, seeded by S |
| S (4 B) | fresh random bytes per signing |
| cert SHA-1 | the app's APK signing certificate (fixed) |
| block (32 B) | mixed output of the VM (carries the claims' fingerprint) |
| claims | the request's parameters, fixed key order |
| digest (32 B) | VM mixing of everything |
| header fields | fixed constants of the app + the blob itself |

Everything is computed offline by `adj9_signer.py`. The only input that
cannot be computed is a **real GAID** — the tracker only re-attributes
devices it already knows.

Code map: `make_header` (TIME) · `region/_d4_words/_d0_words` (region) ·
`build_desc10/claims_for_law` (claims) · `finex_mint` (VM mixing + assembly) ·
`auth_header` (Part A text). Full tour: `HOW_SIGNATURE_WORKS.md`.
