# Corrections + the native SHA-1 (2026-09-09, evening)

Two of my earlier claims were wrong. Both are corrected here with the evidence
that overturned them, plus what remains true.

---

## 1. CORRECTION: "zeroed H / empty map returned the same blob" was an artifact

**What I said:** run4 appeared to show that `nSign` returns the *identical*
192-byte blob when `arg3` (the key2 HMAC) is replaced with 32 zero bytes, and
again when the request map is replaced with an empty `LinkedHashMap`. That would
have proven the blob ignores its inputs.

**Why it was wrong:** the oracle re-invokes `NativeLibHelper.a(...)` by
reflection, and LSPosed hooks the method at the ART entry point — so the oracle's
own call re-enters `afterHookedMethod` and is logged as another `nsign` event.
The `nsign` line immediately preceding each `oracle_*` line **is the probe's own
result**, not the real SDK call. I was comparing each probe against itself.

Proof from `cap/oracle_run4.log` (relative seconds):

```
 +3.368s oracle_start          <- oracle thread wakes
 +3.370s nsign_in              <- PROBE #0 entering (not a real SDK call)
 +4.207s nsign      41e034...  <- PROBE #0 result
 +4.208s oracle_same_0 41e034...   same object, 1 ms later
```

Fixed in Hook.java: added `inProbe`, the hook now stays silent for oracle calls.

**What survives from run4:**
- zeroed `arg3` (32 x 0x00) and an empty map both still return **192 bytes**
- `apiLevel=0` returns **-1** (failure) — the only input that changes the outcome

So: nSign does not need meaningful request data to emit a well-formed blob. It
*is* non-deterministic (every call differs), so input-dependence cannot be
measured by comparing blobs.

---

## 2. CORRECTION: the ".rodata k1/k2" constants are not keys — they are SHA-1

I previously flagged two 16-byte `.rodata` constants as candidate key material.
Read as little-endian dwords they are textbook hash constants:

```
.rodata+0xc0  01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
              = 67452301 efcdab89 98badcfe 10325476     MD5 IV / SHA-1 H0..H3

.rodata+0xe0  f0 e1 d2 c3 99 79 82 5a a1 eb d9 6e dc bc 1b 8f
              = c3d2e1f0 5a827999 6ed9eba1 8f1bbcdc     SHA-1 H4 + K0,K1,K2
```

The 4th round constant never appears in `.rodata` because it is materialised as
an immediate — which is exactly the one SHA-1 constant my earlier `.text`-only
scan reported (1/4).

**Consequence: my earlier "there is no crypto in libsigner.so" verdict is wrong.**
That scan only looked for constants materialised as `mov`/`movk` immediates in
`.text`. The real constants live in `.rodata` (`rev/scan_rodata_consts.py`).

---

## 3. NEW: there IS a native SHA-1, and nSign reaches it

Init function at **0x12e5f4** (11 instructions):

```
0x12e5fc  str  wzr, [x0, #0x40]        ; ctx->len field   = 0
0x12e600  str  xzr, [x0, #0x48]        ; ctx->len field   = 0
0x12e604  ldr  q0, [x8, #0x620]        ; H0..H3
0x12e608  mov  w8, #0xc1d6
0x12e60c  ldr  q1, [x9, #0x640]        ; H4, K0, K1, K2
0x12e610  movk w8, #0xca62, lsl #16    ; 0xca62c1d6 = K3
0x12e614  stp  q0, q1, [x0, #0x50]
0x12e618  str  w8, [x0, #0x70]
0x12e61c  ret
```

Context layout:

```
+0x40  length/counter (zeroed)
+0x48  length/counter (zeroed)
+0x50  h0  +0x54 h1  +0x58 h2  +0x5c h3  +0x60 h4
+0x64  K0  +0x68 K1  +0x6c K2  +0x70 K3
```

That is a standard SHA-1 state (5 words) followed by the 4 round constants.

**Reachable from nSign** (`rev/reach_nsign.py`, bl-only BFS, 418 functions):

```
nSign 0xdb1cc -> 0xda97c -> 0xda6b8 -> 0xe740 -> 0xe3c0 -> 0x12e5f4
```

The other two constant-block readers are false positives: `0x8d400` loads
`.rodata+0xd0` and `0x31924` loads `.rodata+0xf0` — neighbouring dwords that are
offsets/lengths, not constants.

---

## 4. What is still definitively NOT in the library

Re-verified after the `.rodata` gap was found:

| check | result |
|---|---|
| ARMv8 crypto extensions (`aese/aesd/sha1*/sha256*/pmull/eor3/...`) | **0** in 327,541 instructions |
| AES S-box / inverse S-box (whole file) | **0** |
| Blowfish / ChaCha / TEA / CRC32 / SipHash / xxHash / Murmur3 / SM4 / RFC3394 IV | **0** |
| SHA-256 / SHA-512 / MD5 K-tables (whole file) | **0** |
| 64-byte runs with >=58 distinct byte values anywhere in the file | **0** |
| `.rodata` total size | 0x150 bytes (336) — fully accounted for |

`DT_NEEDED`: liblog, libm, libdl, libc only.

**So there is no cipher.** Native crypto = SHA-1 only. Everything else
(SHA-256, MD5, HMAC-SHA256 with key2) is done through JCA via JNI reflection,
which is why it never showed up in the import tables.

Relevant libc imports: `rand`, `srand`, `time`, `clock_gettime`, `gettimeofday`,
`localtime`, `strftime`, `fopen`, `opendir`, `fread`, `access`, `stat`, `fstat`,
`socket`, `__system_property_get`, `syscall`, `getpid`.

---

## 5. NEW: the blob's leading 16 bytes are not full-entropy

`cap/oracle_run7.log` — 24 back-to-back nSign calls (no sleeps, buffered logging):

- 22 distinct leading-16 values out of 24
- 2 exact repeats: calls (4,5) and (10,11)
- **0** repeats at any other 16-byte-aligned offset (176 other blocks)
- every blob is 192 B; call duration 789–2226 ms

`cap/oracle_run4.log` — 30 blobs, 435 pairs: exactly **1** pair shares a prefix,
again 16 bytes.

Two collisions where chance predicts ~2^-128 means the leading 16 bytes come
from a small value space — they are not a 128-bit random nonce.

**But it is not the wall-clock second** (my first hypothesis):
- calls 6 and 7 share a second and share **0** bytes
- pairs (4,5) and (10,11) are in **different** seconds and share 16

`rev/predict_rand.py` tried to reproduce the prefix from the timestamp
(glibc TYPE_3 additive-feedback + 3 LCG variants x 8 byte-extraction rules x
+/-8 s around each blob's timestamp, 30 blobs): **0 hits**. So either bionic's
`rand()` is a generator I did not model, or the seed is not `time(NULL)`.

No concurrency explanation either: in run7 the real SDK signings are at
...304555 and ...344811 / ...358135, entirely outside the rapid-fire window.

---

## 6. What this means for the "server decrypts device data" model

Supports it:
- nSign emits a well-formed 192 B blob even with a **zeroed** key2 HMAC and an
  **empty** request map. The output is not a function of the request.
- The blob carries device material (the library reads files, system properties,
  and the BKS trust store) and is randomised per call.
- Therefore Adjust cannot be verifying "this signature matches this request" —
  consistent with "it validates device data after unpacking".

Does **not** support a literal decryption:
- there is no cipher in the library, and no key material anywhere in the file
  (zero high-entropy constant blocks). There is no app-side secret that could
  serve as a shared decryption key.
- with only SHA-1 and `rand()`, the blob is far more likely to be
  hash/PRNG-derived device material plus a nonce — i.e. something the server
  **parses and cross-checks**, not decrypts.

Open:
- what exactly feeds the native SHA-1 (update/final not yet located)
- where the BKS keystore stream comes from (`ks_load_stream` still captures null)
- the 16-byte leading value's generator
