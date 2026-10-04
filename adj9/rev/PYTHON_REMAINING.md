# WHAT REMAINS — signature making & decrypting in Python

Status as of 2026-09-10. Two questions: (A) can Python **make** an adj9
signature, (B) can Python **decode** one. Short answer: A = **no** (one hard
wall), B = **partly** (header yes, body open pending one experiment).

---

## 0. Already Python-complete (nothing left)

| piece | tool | evidence |
|---|---|---|
| 16-byte header | `rev/header_gen.py::make_header(unix_sec)` | 36/36 + 24/24 on-device **and 4/4 on live server-accepted traffic** (`SAZ_LIVE_TRAFFIC.md` §2) |
| `adj_verification` | constant | byte-identical to live traffic |
| `adj_signing_id` / `algorithm` / `headers_id` / `native_version` | constants | read out of the live decrypted string table |

⇒ Python can build **everything in the `Authorization` header except the
192-byte `signature` value itself.**

---

## A. MAKING a signature — what remains

`signature = Base64( header(16 B) ‖ body(176 B) )`. Header: done. Body: blocked
by three layers, in increasing hardness.

1. **The fold program** (portable, not yet ported exactly).
   Driver `0x144214(ctx, words*, count)`; primitives `sub_1441e4`,
   `sub_143b20` (slot search), `sub_144074` (XOR-fold). Seed chain:
   `openat("/dev/urandom")` → `read(fd, buf, 8)` → **low 32 bits only** →
   `ctx_init 0x1437ec(ctx, seed)` → Park–Miller `0x13dfd0`
   (a=16807, q=127773, r=2836, mod 2³¹−1) → `shuffle16 0x143c88`.
   Identified from `WALL_A_SLICE_4.md` §1; a Python model exists
   (`rev/seed_model.py`) but the fold loop is not yet exact.

2. **The record** (the fold input) — the canonical `LinkedHashMap.toString()`
   (~1.3 kB, ~50 entries incl. `adj_verification`, excl. the 4 header fields).
   The field *vocabulary* is fully known (live string table); the exact
   serialisation and entry order are not pinned.

3. **`H = HMAC-SHA256(key2)` — THE HARD WALL.**
   New, DB-level confirmation (`device/ks/persistent.sqlite`, penti uid 10392):
   - penti owns exactly two keystore entries: `_androidx_security_master_key_`
     and **`key2`**.
   - `key2` parameters: `ALGORITHM=0x80` (**HMAC**), `KEY_SIZE=256`,
     `MIN_MAC_LENGTH=256`, `security_level=1` (**TEE**), `ORIGIN` present.
   - its material is a **218-byte `pKMblob`** (`70 4b 4d 62 6c 6f 62` =
     `"pKMblob"`) sealed by the TEE master key. The key bytes are not in the
     DB in usable form.
   ⇒ key2 is **non-exportable by any software means** (root included). **No
   Python can compute H.**

**Verdict:** offline Python **minting of a server-accepted signature is not
achievable.** Python can mint the header + `adj_verification` (2 of the 6
header fields), never the 192-byte value. The only genuine mint path is the
**on-device oracle** (LSPosed hook re-invoking `nSign`) — already built in
`adj9/module/`.

### New finding — attestation code is present but NOT used here
The live string table contains a full attestation vocabulary
(`KeyGenParameterSpec$Builder`, `setAttestationChallenge`, `setDigests`,
`setIsStrongBoxBacked`, `generateKeyPair`, `KeyPairGenerator`,
`StrongBoxUnavailableException`, `getSigningCertificateHistory`,
`hasMultipleSigners`). **But penti's keystore has no asymmetric key** — so on
this device the attestation path is not taken (fallback / dead code). Also
note a hardcoded 32-byte constant adjacent to `AndroidKeyStore`:
`b1c22b0c02505175fdc8651d3a623c0499fcec04941db33f1f83aae7701faa16` (va
`0x1536d0`) — candidate fixed attestation challenge or fixed key. Unresolved.

---

## B. DECRYPTING a signature — what remains

### B1. Header (16 B) — DONE
It is `f(time(NULL))` and nothing else. To recover the second from a captured
request, brute-force a small window around the request's own `created_at`
(observed offset: **+1 s**, consistent over 4/4 live requests). Fully
implemented.

### B2. Body (176 B) — OPEN

What it needs, in order:
1. The exact fold program (§A.1).
2. The fold input record (§A.2).
3. Then, **if** the body's only secret input is the seed: brute-force the
   **≤2³¹** seed by forward-simulating the fold and matching a captured blob.
   The seed space is small enough to be trivially tractable.

### THE decisive open question (settles B2)

> **Is `H` an input to the 176-byte body transform?**

- **If NO** → the body is a function of (record, ≤2³¹ seed) only ⇒ offline
  decode by seed brute force is **viable** once the fold is ported.
- **If YES** → the body is keyed by a TEE-only secret ⇒ offline decode is
  **infeasible, full stop**, exactly like minting.

Current evidence is contradictory and must be resolved by experiment:
- `NSIGN_REVERSAL.md` / memory: "nSign **recomputes H internally** (arg3
  ignored — the zero-H oracle still returns a valid 192 B)". If nSign computes
  H itself and folds it in, H is an input ⇒ the body is keyed.
- But the oracle's zero-H call returned 192 bytes — that only proves it
  *returns* something, not that the server would accept it.

---

## C. The cheapest experiments that move this

1. **Hook the fold entry, not the stack.** Hook the native
   `0x143794`/`0x144214` (or the `read(/dev/urandom,8)` at `0x13e6b0`) and log
   its arguments. **One hook settles the decisive question in §B2** and gives
   the seed directly — this replaces the whole stack-capture approach that
   failed (`SAZ_LIVE_TRAFFIC.md` §5: the ctx is in `.data`, and the per-call
   state is not in the dumpable regions we scanned).
2. **Controlled-seed test.** Set the device clock to a known second, trigger a
   signing, and capture the blob. The header seed is then known; test whether
   the body is reproducible from (record, seed) alone. If it is, §B2 is solved
   by brute force; if it is not, H is an input and §A's wall also blocks B2.
3. **Port the fold exactly** (`0x144214` + the three primitives) — needed for
   either outcome, and the only remaining static work.

## D. Bottom line

- **Making:** permanently blocked offline by key2 (TEE). Oracle-only.
- **Decoding:** header solved; body is one experiment away from a yes/no.
  If H is not an input, decode becomes a ≤2³¹ seed search — cheap.
  If H is an input, decode is blocked by the same TEE wall as making.
