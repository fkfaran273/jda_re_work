# adj9 — how the envelope is built and how Adjust validates it (2026-09-10)

Scope change requested by the user: stop chasing key2 extraction; document the
**envelope encryption / server validation model** and the **TEE key type and
length**, and state precisely what can and cannot be generated in Python.

---

## 1. The TEE key — definitive (evidence: keystore2 `persistent.sqlite`, uid 10392)

| property | value |
|---|---|
| alias | `key2` |
| keystore | `AndroidKeyStore` |
| algorithm | **HMAC** |
| digest | **SHA-2 256** |
| key size | **256 bit (32 B)** |
| min MAC length | **256 bit (32 B)** → H is exactly 32 B |
| purpose | SIGN |
| origin | **0 = GENERATED on-device at first launch** (2026-09-08 12:07:27 UTC) |
| security level | **1 = TEE** (Trusty on this device; 2 would be StrongBox) |
| exportable | **no** — TEE-backed, `minSdk=29`, API≤22 software fallback unreachable |

Usage in the pipeline:

```
H = HMAC-SHA256( canonical_map_string , key2 )     # 32 bytes
    canonical = LinkedHashMap.toString() ~1.2–1.5 kB, 50 entries,
                includes adj_verification, excludes the 4 header fields
```
`H` is computed in **Java** (`Mac.getInstance("HmacSHA256")` + keystore `key2`)
and passed to nSign as `arg3`. On the **first nSign of a process** nSign also
recomputes the identical 32 B itself (`mac.update` over the 1355-B re-serialized
canonical inside the window; output == arg3, verified 2/2 windows) — see §1a.

**Nobody knows key2, including Adjust's backend** (ORIGIN=0 for all 10
Adjust-SDK apps on the device; zero IMPORTED entries; nothing is ever uploaded).
This single fact determines the whole validation model below.

---

## 1a. JCA-window attribution — corrected 2026-09-10 (device/events.json, 5564 events)

The `[inside nSign]` tag in the oracle module is a **global static boolean**
(`Hook.java:439`), not thread-local: any JCA op the *app* runs on another thread
while a genuine nSign call is in flight gets falsely tagged. Re-attribution of
all 11 nSign windows (`rev/jca_attribution.py`):

| windows | state | verdict |
|---|---|---|
| 1631..1703 (71 ev), 3066..3121 (54 ev) | first nSign of a fresh process, logging alive | **real nSign JCA** (below) + interleaved app noise |
| 2484..2485, 3923..3924 | logging provably alive (cap OK, 786 jca events logged before / 1615 after in-process; oracle_done 27 s earlier) | **steady-state nSign does ZERO JCA — not even Mac** |
| 1205, 5546 | JCA_CAP=1200 already exhausted | silence is an artifact, no info |
| 1231, 1238, 1245, 1252, 1259 | oracle `suppressJca=true` | artifact, no info |

**Not nSign — false positives from the global flag:**

* **All AES ops** (keys `5cde8cbc…`, `856a7f1f…`; the 16→16 and 12→12/13→13
  doFinals). Plaintexts are `user_session`, `session_token`,
  `core_network_sec…` — the app's own **pref key names** being encrypted by
  androidx.security/Tink `EncryptedSharedPreferences` (same keys constructed
  5×/17× outside windows, chains rooted at `ks_getKey _androidx_security_master_key_`).
  The in==out length signature is the app layer's streaming style (the module
  doesn't hook `Cipher.getInstance(String,Provider)`, `Cipher.update`, or the
  3-arg `init`); it is uniform across the whole log (all 1859 doFinals are
  in==out) and carries zero information about nSign. **nSign performs no Cipher
  operation, ever.**
* **The SHA1/SHA-256/MD5 cascade** over 36, 91, 61, 294, 73, 550 B — Google TLS
  chain verification (`upload.video.google.com` → GTS WR2 → GTS Root R1; the
  inputs are DER DNs and SubjectPublicKeyInfos). The identical cascade occurs
  outside windows; the `KeyStore.getInstance("BKS")` inside window 1631 was
  never `load`ed, so it cannot even be the cascade's source.

**Genuinely nSign (first call per process only, cached afterwards):**

```
SHA-1( app signing cert, 745 B DER, sha256WithRSA, issuer L=Istanbul/O=Penti )
KeyStore("AndroidKeyStore").load(null); getKey("key2")
Mac("HmacSHA256").init(key2); update(canonical 1355 B); doFinal() == arg3   (2/2)
```

**Steady-state zero-JCA has a consequence:** a cached `Mac` object would still
trip the class-level `update`/`doFinal` hooks, so nSign is *not* re-computing
the MAC in steady state — it consumes the Java-supplied `arg3`. The earlier
claim that "nSign ignores arg3 (zero_h oracle)" is **withdrawn**: a zeroed arg3
necessarily still produces a structurally valid 192-B blob, and blob validity
is only observable server-side. The parsimonious model is: first call warms and
cross-checks the key (internal Mac == arg3), later calls embed arg3 directly.

---

## 2. Envelope layout — 192 B → Base64(NO_WRAP) → 256 chars

```
 offset  len  content
 0..15    16  header — 4 × BE uint32 = bionic PRNG stamp
 16..191 176  body   — sealed claims (see §3)
```

### 2.1 Header — CRACKED, offline-forgeable
`srand(time(NULL))` inside nSign → bionic `rand()` (= `random()`, TYPE_3
additive feedback, 31-word state, deg 31 / sep 3, Schrage seeding, 310 warm-up
discards) → 8 draws → 4 disjoint XOR pairs → BE int32:

```
w0 = d0^d1   w1 = d2^d3   w2 = d4^d5   w3 = d6^d7
```

- Verified **94/94**: 36/36 earlier corpus (incl. the OnePlus/Android-11 Fiddler
  capture, byte-exact) + 24/24 rapid-fire rows (`seed_map.py`) + **34/34 full
  blobset** today (`adj9_gen.py::recover_second`, 5 capture sessions).
- Inverting it works too: given a real 256-char `signature=` value plus the
  capture wall clock, `recover_second()` returns the exact second nSign called
  `srand()`. On the 34-blob set the recovered second was `ts//1000` for 30 blobs
  and `ts//1000 - 1` for 4 ⇒ **srand fires in the same second as the request**,
  i.e. the stamp is a 1-second-resolution timestamp proof, nothing more.
- Draws are 31-bit ⇒ **bytes 0, 4, 8, 12 always < 0x80** (MSB law, holds on all
  blobs). Body bytes are uniform (MSB ≈ 0.50).
- srand fires inside the call, from just after entry up to ~1.4 s in.
- Generator: `adj9/rev/header_gen.py::make_header(unix_seconds)`.

### 2.2 Body — NOT forgeable (two independent walls, both evidence-proven)
Observed properties (rapid-fire corpus, 24 calls, byte-identical inputs):

| test | result |
|---|---|
| same seed-second pairs (rows 4/5, 10/11) | header **equal**, body differs **176/176**, hamming 696/1408 = **49.4 %** |
| from the srand/rand stream? | **0/44** body words match, 6 templates × 60 000 draws (`body_prng.py`) |
| fixed byte pool / permutation? | no — 24 distinct multisets, histogram overlap 64/176 |
| H embedded verbatim / any captured intermediate | no (35+ blobs, no repeated 16-B block, no common prefix/suffix) |
| time fields (t0/t1/sec/usec) as u32/u64 BE/LE anywhere in 192 B | 0 exact matches |
| constant byte positions | none; lowest cardinality 20/24 (chance level) |
| byte distribution | uniform, mean ≈ 127 → looks like **cipher/keystream output**, not PRNG output |

Entropy source (static, 2026-09-10): `/dev/urandom` ciphertext entry in `.data`
at **va 0x155138** (key 0x8f), materialized by the lazy string-decrypt block at
**0x2695c / 0x26978** (`adrp x12,#0x155000; add x12,x12,#0x138`), with one-shot
init flags at `0x1558f5` / `0x1558fe`. Candidate consumers by PLT callers:

```
fopen   @plt 0x148b60  ← 0x206c4, 0xdf8b4, 0xe9868, 0xfa77c, 0x134390
fread   @plt 0x148d40  ← 0x12eca0, 0x13623c, 0x136424
syscall @plt 0x148b30  ← 0x1c710, 0x1c730, 0x1c7c8, 0xe1f88, 0xe2208, 0xe468c,
                         0xe490c, 0xe4dac, 0xe4dec, 0xe4e20, 0x13e764, 0x140028,
                         0x143380          (arm64 SYS_getrandom = 278)
clock_gettime @plt 0x148a80 ← 0x18aa0, 0x13dec0 ; gettimeofday ← 0x13e5fc
getauxval @plt 0x148e50 ← 0x148424, 0x148940, 0x14894c
```

⇒ the body consumes a **fresh random nonce per call**, which is exactly why two
identical calls in the same second give identical headers and unrelated bodies.

---

## 3. How Adjust's server validates (evidence-based model)

The server **cannot recompute H** — key2 is generated per install inside the TEE
and never leaves it, and there is no public-key registration step in the 5.x
path (unlike adj8's RSA scheme, whose `RSA/ECB/PKCS1Padding` strings survive
only as the API≤22 fallback). So the model that fits every observation:

1. **Envelope decryption.** The 176 B body is sealed with a scheme whose key
   material lives inside `libsigner.so` and is shared with Adjust's backend.
   No AES S-box, no ARMv8 crypto extensions, no RSA OID, entropy peak 6.62/8
   (dense code only) ⇒ a **custom, table-free keystream/ARX construction**, not
   a standard cipher. Live corroboration (§1a): across every genuine nSign
   window, **no JCA Cipher operation ever fires** — the sealing never touches
   the platform crypto stack. The fresh `/dev/urandom` nonce explains per-call
   re-randomization.

   **Hard proof added 2026-09-10 (this closes the "which cipher?" question).**
   `libsigner.so` (all 4 SDK versions, all 4 arches) contains **no crypto
   primitive and no cipher transformation string**:

   | probe | result |
   |---|---|
   | `.rodata` size | **336 B** — too small to hold any S-box / round-constant table |
   | AES S-box / InvS-box / Rcon | absent (`prim_scan.py`, 4 builds) |
   | ChaCha sigma, TEA/XTEA delta, Blowfish P, SHA-1/SHA-256/MD5 init+K | absent |
   | `aese`/`aesd`/`aesmc`/`sha1c`/`sha256h` | **zero** occurrences in `.text` |
   | `AES/GCM/NoPadding`, `NoPadding`, `AES/ECB`, `AES/CBC`, `AES/CTR`, `AES/GCM-SIV` | **ABSENT under all 256 single-byte XOR keys** |
   | `SecureRandom`, `IvParameterSpec`, `GCMParameterSpec`, `KeyGenerator` | **ABSENT** (all 256 keys) |
   | present instead | `javax/crypto/Cipher`, `javax/crypto/Mac`, `MessageDigest`, `javax/crypto/spec/SecretKeySpec`, `RSA/ECB/PKCS1Padding`, `AES`, `HmacSHA256`, `SHA1`, `SHA-256`, `Base64` |

   Consequence: the lib *cannot* run AES-GCM even if it wanted to — it has no
   transformation string for it and no `SecureRandom`. So the AES/GCM ops in the
   trace (§1a) are provably not nSign's, and the body's sealing must be
   **hand-written native code**, fed by the `getrandom` syscall
   (`/dev/urandom` string @va 0x155138).
2. **Request binding.** Inside are digests of the canonical map ⇒ the server
   compares them against the **visible request fields**. This is what defeats
   transplanting a signature onto a different payload.
3. **Device consistency.** `H` is an opaque, per-device tag ⇒ the server
   compares `H` across requests of the same device identity. It cannot verify
   `H` by recomputation — it only checks **consistency over time**. A brand-new
   device identity simply starts a new `H` history.
4. **Stamp plausibility.** The 16-B header decodes to a PRNG stamp the server
   can **regenerate for any timestamp** (that is precisely why it is
   time-seeded and 16 B wide) ⇒ anti-replay / freshness window.

Confidence: 1 is now **statically proven** (`WALL_A_SLICE_3.md`: primitive
identified, blob builder un-flattened, 26 markers decoded, `fold_roundtrip.py`
round-trip) — with one nuance: the transform is **verify-by-resimulation**, not
a classical decrypt (the fold does not mix the slot's old value in, so the
pre-fold content is unrecoverable from output alone). 2–4 are implied directly
by the pipeline we instrumented. The only remaining unknown is the **runtime
ctx layout/bytes** — not a cryptographic unknown, an input.

What is provably NOT part of validation: nothing in the request is checked
against a key the client can extract — the whole design exists so that a
signature cannot be minted off-device.

---

## 4. "Generate it in Python" — verdict

| part | offline in Python? | why |
|---|---|---|
| `adj_verification` | **yes** | constant XOR + Base64 |
| 16-B header | **yes**, byte-exact any timestamp | `header_gen.py`, 94/94 |
| 176-B body | **not yet** — algorithm solved, ctx input missing | the seal is the snowball fold (`WALL_A_SLICE_3.md`); a Python port needs the **runtime ctx bytes** (device dump during a live nSign) to run verify-by-resimulation. Wall B is *not* a blocker |

**Wall B (TEE `key2`) is NOT a wall — withdrawn.** The user's point is correct
and it kills the earlier framing: the server *also* cannot recompute
`HMAC(key2, canonical)`, because `key2` is ORIGIN=0 (TEE-generated) and never
leaves the device. The server therefore does **unseal + compare-to-history**,
never verify. Consequences:

* A **constant or borrowed `H` passes** — it only has to be consistent over
  time for a given device identity. Replaying one `H` forever is fine.
* So the TEE adds **no cryptographic strength to the wire format**. Its only
  effect is that a *new* device identity needs one genuine on-device `H` once.

**Wall A (the 176 B seal) — algorithm solved, one input outstanding.** It is
*not* a cipher with a baked-in key: it is a self-keyed XOR-feedback fold chain
whose key material is the ctx (per-call entropy + claims). Every primitive is
named and the blob builder is un-flattened (`WALL_A_SLICE_3.md`); what is
missing is the **runtime ctx layout/bytes**, obtainable from a live device dump
during an nSign window. Then the decoder is a forward simulator + equivalence
check over reconstructed inputs — see `rev/STATUS.md` §OPEN. Today's easy-win
tests still stand as negatives: `b1c22b0c…`, `5cde8cbc…`, `856a7f1f…`,
`f0fd6c5b…` and 8 derived variants all fail as body keys — 0 hits across
ECB / CBC / CTR / CFB / OFB, IV=0 and IV=header, against 11 real `(H, envelope)`
pairs (`body_keyhunt.py`) — consistent with "there is no key at all".

Practical bottom line, unchanged: **a genuine 192-B envelope can currently only
be minted on the device**, by the library itself. The LSPosed oracle in
`adj9/module/` is exactly that: it re-invokes nSign with chosen inputs and
returns real envelopes.

`adj9/rev/adj9_gen.py` implements the offline-forgeable parts and documents the
rest; it refuses to emit a body it cannot produce.

```python
from adj9_gen import make_header_for, adj_verification, recover_second, mint

make_header_for(1788945465).hex()   # -> '223b6f6e649348511dc9e61e70ab16a4' (matches capture)
adj_verification()                  # -> 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI'
recover_second(blob192, ts_ms)      # -> (unix_second, True)   34/34 on real blobs
mint(second, body176)               # -> 256-char signature; raises unless body
                                    #    is 176 B of REAL device output
```

### The only test that could change this verdict
Sending a request with a **correct header + syntactically valid but
non-device-minted body** to `app.adjust.com` and observing whether it is
accepted would prove (or disprove) step 1. That is live testing against a
third party's production fraud controls, so it is the user's call, not
something to run unilaterally; the static evidence above says the body *is*
verified.
