# Wall A — slice 2: the crypto inventory is settled (2026-09-10)

Continues `WALL_A_SLICE_1.md`. This pass settled WHAT primitives exist, found the
native SHA-1 the earlier pass missed, built a working O-LLVM un-flattener, and
negatively resolved the "embedded shared key" hypothesis for the string/rodata
surfaces. Scripts: `scan_cipher_consts.py`, `unflatten.py`, `walk_machine.py`.

---

## 1. Correction: libsigner DOES contain a native SHA-1/MD5-family implementation

The earlier verdict "no hash implementation" (from `scan_consts.py`, which only
scanned mov/movk immediates) was a scanning artifact. The init vectors live in
**.rodata as plain dwords**:

| va | content |
|---|---|
| `.rodata+0xc0` (va 0x3620) | `67452301 efcdab89 98badcfe 10325476` = SHA-1/MD5 H0..H3 |
| `.rodata+0xe0` (va 0x3640) | `c3d2e1f0 5a827999 6ed9eba1 8f1bbcdc` = SHA-1 H4 + K0..K2 |

The functions:

```
0x12de60  SHA-1 block compress  (writes working vars back to ctx+0x50)
0x12e5f4  SHA-1 init            (loads H0..H3 + H4/K0..K2, K3=0xca62c1d6 inline)
0x12e620  SHA-1 update          (bl 0x12de60 at 0x12e730)
0x12e7d0  SHA-1 final
0x0e57c   the ONLY direct caller of init  (fn 0xe3c4):
              init(ctx@sp+0x30); update(ctx, [x8+8], [x8+0]); final(ctx, x29-0x24)
          — one-shot SHA-1 over a {len, ptr} pair held in a struct
```

This also **re-interprets the old ENVELOPE_HUNT "two 16-byte key candidates"**
(`0123456789abcdeffedcba9876543210`, `f0e1d2c39979825aa1ebd96edcbc1b8f` loaded at
`0x12e5f4` with "magic 0xca62c1d6"): they are the SHA-1 IV and K constants, not
keys. The AES/XOR tests against them were meaningless.

The 0x6ad54 `0x10325476` hit is an O-LLVM dispatcher opaque predicate (verified),
not a second hash instance.

## 2. Cipher inventory — negative, with targeted scans

`scan_cipher_consts.py` (mov/movk in .text + aligned dwords in .rodata/.data):

| family | result |
|---|---|
| ChaCha/Salsa sigma | 1/4 words (noise) |
| TEA/XTEA delta 0x9E3779B9 | 0 |
| SM4 FK/CK | hits at 0x3ddfc/0x3ec08/0x3fedc — **disproved**: disassembly shows 64-bit opaque-predicate tokens (`0x2024_9104_8c93_4b8c`), half-coincidences |
| Blowfish pi | 3/5 (noise; no P-array table in .rodata) |
| Murmur3 / xxHash / FNV / CRC32 | FNV 3/3 real, CRC32 real, xxHash partial — checksum/fingerprint material |
| AES S-box | still absent (no 256-byte bijection) |

Also swept the full decoded string table (511 entries) for high-entropy /
hex / binary key material: **the only candidate is the 62-char hex string
`c22b0c02…faa16` at 0x1536d2, which has zero code xrefs** (re-checked with the
corrected adrp+add pairing) — dead data or decoy.

**⇒ There is no embedded cipher key anywhere we can find.** Combined with §4,
this tilts the model: the 176-B body is probably hash-based whitening
(SHA-1/MD5-family over nonce + claims), not a keyed cipher with a secret shared
with Adjust's backend.

## 3. The O-LLVM un-flattener works

`unflatten.py` parses the dispatcher at 0x24a40 (fn 0x248e0) as a token state
machine: 68 real tokens + 35 alias transitions, **0 unresolved**. Key mechanics
learned (needed for any future walk):

- state travels in `x9` (head does `mov x8, x9`);
- inline candidates materialize in `x9`/`x12` (interleaved — simulate, don't
  pattern-match), and **x9..x15 + x19..x28 are all token registers** (prologue
  materializes 15 of them; missing x10/x11/x13/x14/x15 was why the first parse
  had dangling aliases);
- `b.eq 0x24a40` = alias: state := the token materialized in the *other* register;
- `csel` in capstone has **3 operands** (condition in the mnemonic text) — parse
  from `op_str`;
- blocks may exit with a **direct branch to another block**, bypassing the
  dispatcher (tail-linking) — follow via block2tok.

`walk_machine.py` DFS-walks the machine printing per-block summaries. The 0x24a40
machine is the **fingerprint / emulator-detection routine** (`init.nox.rc`,
`/system/build.prop` string decrypts, one-shot CAS guards at 0x1556c0-0x1556d0).
The seal is elsewhere — likely in fn 0xe3c4's own machine (see §4).

## 4. JNI exit path and remaining anchors

- Generic JNI helpers: `NewByteArray` (env off 0x580) at 0x104f8/0x9e580/0xa7738/
  0x12c328; `SetByteArrayRegion` (0x558) wrapper at 0x9e774 (own dispatcher
  0x9ebf8). Lengths are caller-supplied — no 192/0xc0 immediate anywhere near.
- `fread` sites are generic (4/8-byte file parsing); the urandom read must go
  through the raw `syscall` PLT path. The "/dev/urandom" string consumer is still
  unpinned (the first xref attempt had a stale-register false positive; redo
  per-block).
- Highest-value next static target: **un-flatten fn 0xe3c4** (the native SHA-1
  user) — it has its own dispatcher hub; the same tooling applies. It will show
  what data is SHA-1'd and where the 20-B digest flows.

## 5. Offline cryptanalysis attempt (negative)

Tested self-keyed keystream hypotheses on the 4×24 rapid-fire corpus (identical
inputs, known H): nonce = body[:16/20/32], keystream ∈ {SHA1-chain, SHA1/SHA256/
MD5-CTR LE/BE, SHA1+salt}: **no variant produced identical plaintexts across the
24 same-input blobs, and H never appeared**. The naive "nonce in body[0:n],
SHA-CTR after" layouts are ruled out; the construction mixes inputs differently
(H or other material into the keystream, or a different framing).

## 6. Consequence for the validation model

If §2's negative holds (no embedded key), the server-side story simplifies:
the body must be **self-describing** (nonce transmitted inside the blob; server
re-derives the whitening from the nonce + visible request data) and the true
anti-forgery is exactly the TEE-derived H tag + timestamp stamp + digest
consistency. The remaining unknown is the precise mixing — recoverable by
un-flattening 0xe3c4 (static) or by the deterministic-nonce experiment (device:
bind-mount a fixed file over /dev/urandom in the app mount namespace → same
inputs ⇒ identical bodies → known-plaintext differential offline).
