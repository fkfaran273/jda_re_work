# _sub_alg_RESULT.md — Algebraic identification attempt, iOS 16-byte signature headers

Date: 2026-10-01. Data: `_sub_ios_timing.json` (30 requests → 28 distinct headers).
Scripts (this folder): `_sub_alg_data.py`, `_sub_alg_lcg.py`, `_sub_alg_gf2.py`,
`_sub_alg_seedx.py`, `_sub_alg_struct.py`, `_sub_alg_bitbias.py`.
Machine-readable outputs: `_sub_alg_lcg_out.json`, `_sub_alg_gf2_out.json`,
`_sub_alg_seedx_out.json`, `_sub_alg_struct_out.json`, `_sub_alg_bitbias_out.json`,
`_sub_alg_headers.json`.

---

## 0. Data extraction (one important correction)

* The `authorization.header16_hex` / `adj_verification_b64` field in the JSON is a
  **constant 27-byte blob identical in all 30 requests** (`2a57001b671b000b...07431b`) —
  it is NOT the per-request PRNG header.
* The real header is the **first 16 bytes of the 192-byte decoded signature**
  (`base64.b64decode(signature_b64)[:16]`). Same-second requests share it
  (verified: sids 142/143/144, second 1787553341–3342); bytes 16..191 of the
  signature differ per request even within the same second (header = per-second
  value, body = per-request ciphertext — consistent with the Android
  header-as-whitening-IV design).
* 28 distinct headers extracted. **31-bit law confirmed on the extracted data:
  112/112 BE words < 2^31.** Little-endian word packing fails the law (57/112
  words ≥ 2^31) → **packing is big-endian** (independently re-confirmed).
* Per-header candidate signing seconds: 24 headers have a 1-second ambiguity
  ([t, t+1]); header 23 has 4 candidates; header 25 has 3. 53 distinct candidate
  seconds total.

The 28 headers (words = BE uint32 w0..w3):

| idx | header16_hex | seconds (candidates) |
|----|--------------|----------------------|
| 0 | 3be1d83d6b8eae543eb1a8a5757ca3d6 | 1787553341–3342 |
| 1 | 7032bfb41df49d64635f7fdf77692880 | 1787553342–3343 |
| 2 | 1e81a0e358d3435d53e19372326ae6cc | 1787553344–3345 |
| 3 | 2aa273867af137e645c00ff372140080 | 1787553733–3374 |
| 4 | 445f276a44223915169583790e380479 | 1787555529–5530 |
| 5 | 1ce776e8624d3f484b17fb9c40f720c9 | 1787555693–5694 |
| 6 | 3adbbd0759adff20262f526c2109d6b7 | 1787555748–5749 |
| 7 | 6f5f4b1f4beb933e27e018ab13adc93b | 1787555752 |
| 8 | 12eaa7fd20919ccf207c6ae955a028b5 | 1787555853–5854 |
| 9 | 34b9910157bf2ae7500a6c541263f6c7 | 1787555855–5856 |
| 10 | 476489b5738b89fb28cc910a7f465e21 | 1787555856–5857 |
| 11 | 036ca82810a27af207a753a402a64c11 | 1787556043 |
| 12 | 729afe9c161726a64f75a6ba3fec087d | 1787556292–6293 |
| 13 | 735662911f2170f664b7694e1f60ff21 | 1787556407–6408 |
| 14 | 3b2821db5616cf396f85b2d31f1f8ea8 | 1787556873–6874 |
| 15 | 74720810129ebec14c964a612ae13c2c | 1787557023 |
| 16 | 274681592263be742291b34f39687c94 | 1787557040–7041 |
| 17 | 0a1b66ae13cd36ee477b73072626bd45 | 1787557197–7198 |
| 18 | 2507395c6995ba9a1442323631a7fc0c | 1787557215–7216 |
| 19 | 1b906c1b49bc684b7fddb2e25cf6662f | 1787557236–7237 |
| 20 | 519834e200c5d00642c7666b03f42c1f | 1787557248 |
| 21 | 6239e07c20154509440db2c774acbeab | 1787557263–7264 |
| 22 | 6f875f641afb7b44219daf767b8c2a9c | 1787557278–7279 |
| 23 | 072738427633346a502600121257ab23 | 1787557289–7292 |
| 24 | 47c27b427fa169186ff0e1ce72fd7b03 | 1787557308–7309 |
| 25 | 506235a4489efc155203f69a01448c9f | 1787557324–7326 |
| 26 | 5ac321ee407b691b6e40838d3a6ab159 | 1787557445–7446 |
| 27 | 06bf02d81386784b19b1aee71947b4f9 | 1787557517–7518 |

---

## 1. POSITIVE RESULT — the one significant structural signature: bit 13

**The only statistically significant structure found: bit 13 (counting LSB=0) of
the words is set far more often than 1/2, consistently in all four word slots.**

* Aggregate ones-count over the 112 words: **bit13 = 77/112 = 0.6875** (z = +3.97
  vs binomial(112, ½)); bit25 = 71/112 (z = +2.83); all other 29 bits within ±2σ.
* Per-slot ones-counts (n=28 each): bit13 = **[20, 20, 18, 19]** for w0..w3 —
  high in *all four slots simultaneously*. Monte-Carlo calibration (20,000 reps
  of 28×4 uniform 31-bit words): P(some bit has all four slots ≥ 19/28) =
  **1.0e-4**; P(aggregate ≥ 77/112 at some bit) = 1.6e-3. → not multiple-testing noise.
* Within-header bit-13 popcounts: {0:×2, 2:×7, 3:×13, 4:×6} — **popcount 1 never
  occurs** (uniform-word expectation ≈ 7 headers; p ≈ 1e-3). The four words of a
  single header share a per-second bit-13 tendency → **the four words are derived
  from a shared per-second state, they are not 4 independent draws of independent
  entropy.**
* Incompatibility probe: the probability that bit 13 *disagrees* between two
  consecutive draws is 0.5000 for bionic Random3 (n=59,700 draws), 0.498 for
  lrand48, 0.499 for MINSTD. Under the Android pair-XOR layout
  (w_i = d_{2i} ^ d_{2i+1}) any of these generators pins word-bit-13 at exactly
  0.500 — **so the observed 0.6875 rules out "pair-XOR of consecutive draws"
  from all three standard families, regardless of seed.** (XOR of two
  identically-biased bits can never exceed bias 0.5; exceeding it requires
  negative dependence between the two draws' bits, or a non-XOR composition.)
* The observed within-header patterns (mixed 0/2/3/4, never exactly 1) also do
  not match the simple degeneracies of a truncated LCG mod 2^31
  (a ≡ 1 mod 2^14 with c mod 2^14 ∈ {0, 2^13} would give per-header
  all-equal or strictly alternating bit-13, not observed).
* No seed-bit leak: associating any word-bit with any bit of the candidate
  second (4×31×22 = 2,728 tests) gives 6 hits at |z|>3 ≈ 7.4 expected false
  positives → nothing significant.

**Interpretation.** Bit 13 behaves as if the composition that produces each word
from the generator state flips bit 13 with probability ≈ 0.69 (e.g. XOR of two
stream draws at a larger lag, of a stream whose bit-13 is anti-correlated at
that lag; or a sum/difference-based composition whose carry chain biases bit
13; or single draws of a generator with genuine bit-13 bias). Together with the
per-header stickiness, this is a real fingerprint of the generator/composition —
but it does not by itself identify either. It is the strongest available handle
for the next stage (see §8).

Everything else below came back negative; each negative is a real exclusion.

---

## 2. Attack 1 + 2 — algebraic LCG solve, direct-draw model: ALL RULED OUT

Method (`_sub_alg_lcg.py`): per header, solve w1 = a·w0+c, w2 = a·w1+c for all
(a,c) (general solver: handles even differences via 2-adic valuation, up to 2^20
candidate solutions), then require w3 = a·w2+c. Cross-header: intersect exact
(a,c) sets; ANY (a,c) fitting ≥ 2 headers would be the generator.

| model | self-consistent headers | shared (a,c) by ≥2 headers |
|---|---|---|
| BE words, mod 2^31 | **0/28** | none |
| BE words, mod 2^32 | **0/28** | none |
| BE words, mod p = 2^31−1 (MINSTD prime) | **0/28** | none |
| LE words, mod 2^31 | **0/28** | none |
| LE words, mod 2^32 | **0/28** | none |
| LE words, mod p = 2^31−1 | **0/28** | none |

Not a single header admits even ONE (a,c) fitting its own four words (chance
expectation ≈ 28·2⁻³¹ ≈ 1.3e-8 for ≥1 hit). **Ruled out: w0..w3 as 4 consecutive
direct draws of any truncated LCG x' = a·x+c, mod 2^31, mod 2^32, or mod 2^31−1,
in either byte order — even header-locally, let alone globally.**

## 3. Attack 3 — GF(2) / XOR-linearity: RULED OUT (`_sub_alg_gf2.py`)

* GF(2) rank of the 112 word-vectors (bits 0..30) = **31 = full rank**. No global
  linear law beyond the packing law; no constant bit anywhere (bit 31 dead by the
  31-bit law is the only degeneracy).
* Sparse kernel relations (subsets of the 112 words XORing to 0): weight 2, 3, 4,
  5, 6 — **all zero** (uniform expectations ≈ 0, 1e-4, 0.003, 0.06, 1.1
  respectively; zero weight-6 vs expected ~1.1 is consistent, P≈33%).
* Per-header relations: all 15 subsets of {w0,w1,w2,w3} XOR to zero — **0 of 420**.
  No w2 = w0^w1, no w3 = w0^w1^w2, no parity law.
* Consequence: the words carry no XOR-linear structure of any support ≤ 6.
  If the composition were XOR-of-consecutive-draws of an xor-linear generator
  (LFSR/xorshift) sharing structure across seconds, sparse relations would be
  expected; none exist. (An LFSR re-seeded independently each second is
  unfalsifiable from 4 words per unknown state — noted as an honest limit; the
  bit-13 result of §1 is what constrains that family.)

## 4. Attack 4 — cross-second continuing stream: RULED OUT

(`_sub_alg_lcg.py`) Headers sorted by signing second; words of header t and t+1
treated as 8 consecutive draws (solve from draws 0–2, verify draws 3–7):

| model | consistent pairs |
|---|---|
| BE, mod 2^31 | **0/27** |
| BE, mod 2^32 | **0/27** |
| BE, mod p = 2^31−1 | **0/27** |
| LE, mod 2^32 | **0/27** |

**Ruled out: a single continuing LCG stream across seconds** (no modulus/packing
tested admits even one consecutive-second pair as 8 draws). Combined with §2:
the words are not raw LCG output under any tested modulus, locally or globally.

## 5. Attack 5 — counter/mixed seed families: 0 HITS (`_sub_alg_seedx.py`)

53 candidate seconds; exact 4-word match required (both draw→word layouts:
direct w_i = d_i, and pair-XOR w_i = d_{2i}^d_{2i+1}).

* Generators: bionic Random3 (verified Android generator; 310-draw warm-up) and
  lrand48/srand48 (warm-ups 0..64 for the small families; {0, 10} for the XOR sweep).
* Small families per second (157 seeds × 53 s = 8,321 seeds per generator):
  s, 2s, s·1000≫k (k=0..10), s≫k (k=0..10), s+c (c = −64..64), int(cc·1000),
  int(cb·1000), int(cc), int(cb).
* XOR sweep: s ^ c, c = 0..65535, × 53 seconds = **3.47M seeds per generator**.
* Result: **0 hits everywhere.**

Combined with the prior sweeps (Random3 seed = second ±24 h, glibc/MSVC/Java
LCGs, plain 31-bit LCG, PCG-ish, Darwin randtbl, 8 layouts × 3 seedings), this
kills seed-derivation families g(second) built from small-integer arithmetic,
shifts, and 16-bit XOR masks for the two most plausible generators, in both the
direct and the Android pair-XOR composition.

## 6. Attack 6 — structural analysis (`_sub_alg_struct.py`)

* Byte-level law: word-leading bytes 0/112 high (the 31-bit law); trailing 12
  byte positions: 166/336 = 49.4% high ≈ uniform. **The 31-bit law is the only
  byte-level law; no ASCII/decimal structure** (34/448 hex-digit bytes).
* Within-header arithmetic: consecutive-word differences not constant (mod 2^31
  or 2^32); w0+w1+w2+w3 mod 2^32 distinct across all 28 headers (no checksum
  role); simple equalities (w2 = w0+w1, w0^w1, w0−w1; w3 = w0^w1^w2,
  w0+w1+w2; w1 = w0+w2) — **0/28 each**.
* **w3-as-checksum of w0..w2: 0/28** for sum32, xor, crc32, adler32, FNV-1,
  FNV-1a (BE bytes, LE-packed bytes, and 31-bit-masked variants). All four words
  look like random draws; none is a checksum of the others.
* No repeated words anywhere in the 112 (GF(2) weight-2 search confirms).
* Correlations (Pearson, n=28): all word~word pairs < 0.45; word~second < 0.45;
  w0 ~ second&0xFFFF r = −0.496 is the only one past the 1% line and is at
  chance level given 16 tests (expected ≈ 0.16 false positives) + ±1 s timing
  ambiguity — **not claimed as a signal**.
* Consecutive-second headers: mean Hamming distance 61.96/128 (uniform 64.0);
  smallest word delta 4.29M (P ≈ 35% under uniform) — unremarkable.
* Same-second requests (sids 142/143/144): header16 identical, bytes 16..191 all
  differ → re-confirms header is a pure per-second value, body is per-request.

## 7. Consolidated exclusion list (what each negative rules out)

1. **Direct-draw truncated LCG** (w = 4 consecutive draws of x'=a·x+c):
   mod 2^31, mod 2^32, mod 2^31−1; BE and LE packings. Even header-local
   consistency fails 0/28 — excludes any generator whose *output words* are
   consecutive LCG states under those moduli.
2. **Cross-second single stream** of such an LCG (8-draw windows across
   consecutive seconds): 0/27 under all four moduli/packings.
3. **Pair-XOR of consecutive draws from bionic Random3, lrand48, or MINSTD**,
   for *any* seed — excluded by the bit-13 law (§1: their consecutive-draw
   bit-13 disagreement is exactly 0.5, which would pin word-bit-13 at 0.5, not
   the observed 0.6875). This is independent of, and adds to, the failed
   seed sweeps.
4. **Seed = g(second)** for g ∈ {identity, 2s, s·1000≫k, s≫k, s+c(−64..64),
   s^c(0..65535), wall-clock millis/micros of cc/cb} × {bionic Random3,
   lrand48(0..64 warmups)} × {direct, pair-XOR}: 0 hits.
5. **GF(2)-linear composition** (xorshift/LFSR draws, XOR-combined) leaving any
   relation of support ≤ 6 among the observed words: none exist (rank full,
   kernel min weight ≥ 7).
6. **w3 (or any word) as a checksum of the others** (sum/xor/crc32/adler32/
   FNV, BE/LE, masked): 0/28.
7. **Word-level artifacts**: no repeated words, no constant bits besides the
   packing law, no within-header additive identities, no byte-level structure
   beyond the 31-bit law, no seed-bit leakage into word bits.

## 8. Where this leaves the hunt (recommendation)

The evidence now says: each word is a 31-bit quantity derived from a shared
per-second state through a composition that (a) is not a plain truncated-LCG
output chain, (b) is not XOR-of-consecutive-draws of the standard families, and
(c) systematically sets bit 13 with p ≈ 0.69 while leaving bits 0..30 otherwise
clean and GF(2)-generic. Concrete next probes, in order of promise:

1. **Pair-XOR at lag > 1** (w_i = d_i ^ d_{i+k}, k = 2..8) and
   **sum-compositions** ((d_i + d_{i+1}) ≫ 1, (d_i − d_{i+1}) mod 2^31, etc.):
   measure their bit-13 output rates per family — only compositions that can
   produce 0.6875 are viable, which is a cheap discriminator.
2. **Truncated LCG mod 2^32 with structured (a mod 2^15, c mod 2^15)** scanned
   directly against the bit-13 per-header popcount distribution {0:2, 2:7,
   3:13, 4:6} — the popcount pattern is a stronger fingerprint than the
   aggregate rate.
3. **Splitmix-style mixers** (murmur3 finalizer, splitmix64 low half, xxHash
   avalanche of `second`): these are per-second state → 4-word splitters with
   internal XOR/shift/shift-add stages that CAN bias single bits; run the 28
   seconds (both window candidates) through each mixer and word-splitting order.
4. Re-run the per-second seed sweep with **warm-up as a free parameter 0..4096**
   for MINSTD-family generators, scoring by the bit-13 popcount pattern instead
   of exact match (the pattern may survive small state deviations where exact
   match fails).
