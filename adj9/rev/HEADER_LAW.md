# adj9 Envelope Header — FULLY REVERSED (2026-09-09)

## The law (36/36 blobs, two devices, two Android versions)

```
seed     = time(NULL)          // taken inside nSign, every call
rand()   = bionic random()     // TYPE_3 additive feedback, NOT lrand48
d[0..7]  = first 8 draws after srandom(seed)  (310-discard warmup)
word_i   = d[2i] ^ d[2i+1]     // i = 0..3
header   = BE32(word_0..word_3) // 16 bytes, blob[0:16]
```

## Static evidence (libsigner.so)

Call chain, all confirmed by disassembly:
```
nSign 0xdb1cc
  └─ bl 0xda97c @0xdb898
       └─ bl 0x12cb74 @0xdafe4
            ├─ bl time   @0x12cbbc   (PLT 0x148d20)
            ├─ bl srand  @0x12cbc0   (PLT 0x148d30)  -> srand(time(NULL))
            └─ bl 0x100094 @0x12d39c   (mega-fn, 174KB flattened)
                 └─ rand-loop @0x12a2f8..0x12a414:
                      do {
                        PUSH(rand())  @0x12a2fc
                        PUSH(rand())  @0x12a31c
                        a=POP(); b=POP()
                        PUSH(a^b)     @0x12a368 (eor w2,w0,w21)
                        c=POP(); d2=POP()
                        APPEND(out, c, d2, cnt)  @0x12a3d0 -> 0x146ed8
                        PUSH(POP()+1) @0x12a3f4
                      } while(!EMPTY())  @0x12a414 -> 0x146650
```
The loop is a tiny native STACK-VM (push/pop/append via calloc/realloc/free);
only 2 rand() call sites exist in the entire .so — both inside this loop.

rand-loop reached ONLY from nSign path; srand-fn has exactly 1 global caller
(0xdafe4) — so header PRNG state is reseeded per signing, matching the
same-second → same-header law.

## Runtime evidence

36 unique 192-byte blobs (34 moto g42 / Android 12 via LSPosed hook logs +
1 OnePlus DN2101 / Android 11 from user's Fiddler capture + 1 rapid-fire dupe):
every single header reproduced from its seed second.

## Fiddler ground-truth (OnePlus DN2101, API 30, app 3.12.1)

- sent_at = 2026-09-08T14:05:22.942+05:30 → epoch 1788856522
- srand fires ~700ms into nSign → seed second 1788856523
- `header_gen.py 1788856523` → `40c8114d3f66c6da1f0f75727e1c44e6`
- actual `signature` blob[:16]  → `40c8114d3f66c6da1f0f75727e1c44e6` ✅

## Why every earlier PRNG battery failed

1. Bionic `rand()` is `random()` (TYPE_3, 31-word additive feedback state,
   310 discarded outputs) — earlier tests used lrand48/glibc-LCG/Schrage/
   MT19937/Java Random → all wrong PRNG.
2. The two rand() draws are XORed per word (`d[2i]^d[2i+1]`) before packing —
   raw-draw models could never match.
3. MSB law (bytes 0,4,8,12 < 0x80) is explained: random() returns 31-bit
   values; XOR of two 31-bit values is still 31-bit.

## What this means

- The header is **offline-forgeable** for any timestamp.
- Interpretation: the 4 words look like "lengths/offsets" but are actually
  deterministic PRNG output the server can recompute from the request time —
  i.e. an anti-replay/timestamp check, or key material for the body scheme.
- The 176-byte body does NOT continue the PRNG stream (0/44 words match
  draws 8+), so the body cipher (likely RSA/ECB/PKCS1 per .data strings)
  consumes the header as input — that's the next target.

## Files

- `header_gen.py` — verified generator (Random3 + make_header(sec))
- `type3_xor.py` — the 36/36 verification run
- `body_test.py` — body-not-PRNG negative result
