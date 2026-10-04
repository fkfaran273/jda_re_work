# corpus_seed — per-call seed isolation on the captured signing corpus

Date: 2026-09-23. Pure offline python (`rev/corpus_seed.py`, full output in
`rev/corpus_seed.log`). Corpus: **3 fresh signings from ONE process** (moto g42,
`signings_extract.json`: canonical bytes, 32-B H, 192-B wire blob, ts each) +
**the oracle probe suite** (10 controlled re-signings, `adj9_capture_run1.log`
`type=probe_result`, semantics from `adj9/module/src/com/adj9oracle/Hook.java`
`oracleSuite`) + the region corpora (`rev/all_signings.json` 10 rows,
`rev/desc_det_result.json` 3 rows, of which S0/S1/S2 are byte-identical
duplicates of rows 7/8/9 → 10 unique region signings).

---

## 0. TL;DR

1. **Header law re-confirmed 13/13**: every wire blob's 16-B header inverts
   UNIQUELY to a second via `Random3(srand(sec))`; MSB law 4/4. Seconds:
   fresh = 1790106110/176/196 (gaps 66 s / 20 s, matching ts gaps 66.0/19.7 s).
2. **The wire body contains NO descriptors**: `fad0f10d…` (#9), `bfffffff…` (#8),
   H, canonical bytes, package/device strings and the screen ints appear
   **nowhere** in any of the 13 wire blobs (4-B window searches, both byte
   orders). The task's assumed 48-dword section layout is also arithmetically
   impossible (its sections sum to 55+ dwords vs the 44-dword body). The body is
   the whitened VM output (S1_FULL_DECODE / fin_result model). Per-call
   W0/#2/#4 are only observable in the REGION captures — used instead.
3. **The per-call seed is proven real and is NOT any known input**: with map
   content, H, level AND second all identical, two calls differ in **175/176
   body bytes** (oracle B1~B2, identical 16-B headers). In the region, the
   same-second identical-claims pair S0~S2 differs in W0, X, tile, #2 and
   #4[1..7]. The 3 fresh bodies pairwise differ in 174–176/176 bytes; **no XOR
   component correlates with H^H, canon^canon, header words, second or ms
   deltas** (dictionary scans: 0 hits where chance ≈ 1e-5).
4. **One real structural law found** (the money constant): the per-call #0 tile
   satisfies **U[2] ^ U[0] == R‖R** (both 16-bit halves equal) — **13/13 rows**,
   controls 0/13 (chance 13/65536). Matches the single law `all_laws.json` had
   found on the older 16-row corpus. The per-call tile is NOT uniform random.
5. Every clock/PRNG/counter kinship test FAILED (details §5): the per-call
   material is not srand-stream continuation, not Park-Miller/LCG/xorshift of
   the previous W0, not linear in the second. Best remaining hypothesis:
   process-local entropy (ART identity hashcodes of the per-call map clones /
   heap pointers / a second clock) read during descriptor fill in `sub_8d6f4`.

---

## 1. Parse table

### 1.1 Fresh wire signings (one process, same device/props/claims-shape)

| n | ts (ms) | sec (header-inverted, unique) | canon_len | H (first 12 hex) | map | modCount |
|---|---------|------|-------|---------|-----|----------|
| 1 | 1790106110175 | **1790106110** | 1222 | 9f15bf1f51ac | 53 | 49 |
| 2 | 1790106176174 | **1790106176** | 1222 | ffaf1a7eb4d4 | 53 | 49 |
| 3 | 1790106195890 | **1790106196** | 1209 | b9e3b7f60895 | 53 | 49 |

- Header `make_header(sec)` reproduces blob[0:16] exactly; unique hit in ±10 s;
  MSB law 4/4 (31-bit draws).
- created_at law re-verified: `sec = floor(epoch(created_at)) + 1`
  (created_at epochs 1790106109.916 / 175.996 / 195.851 → sec hits exactly).
- `env_ints` actually read on device: `sdk=31 widthPixels=1080 heightPixels=2237
  densityDpi=420 level=31`. NOTE: heightPixels is **2237 (0x8BD)**, not 2400
  (0x960 = physical panel); both were tested everywhere below.
- fresh1's blob == probe block's `real` blob (same signing; the probe reuses
  signing-1's map/H — verified in Hook.java).

### 1.2 Region rows (10 unique; #0 = 36 dw, #9 = 5, #8 = 4, #4 = 8, #2 = 1, #7 = 1, #10 = claims, #5 = #6 = 0)

Layout law (empirical, fixes the task's "words 0..35" sketch):

```
#0 = W0 (word 0) | X (word 1) | U×8 (words 2..33) | U[0] U[1] (words 34..35)
     U = 16-B tile; X == U[3] in 12/13 rows (S2 is the exception)
#7  = claims length in bytes (unpadded); d10 = claims padded to 4-byte multiple
#9  = fad0f10d 60f93c17 937b2f1e b6c09691 ae7d74bd   (APK-cert SHA-1) — ALL rows
#8  = bfffffff fffffd1f 00070000 00000000            — ALL rows
#5 = #6 = 0 — ALL rows
```

| row | src | W0 | X | U[0] | U[1] | #2 (d2) | #7 | sec |
|-----|-----|-----|-----|-----|-----|---------|-----|-----|
| 0 | hits | 6ca93c67 | aeca29cb | a47f3a1c | b7a87905 | 41aa16f5 | 502 | 1789239391 |
| 1 | hits2 | c3edf4e0 | cfdd32d2 | 51e79ea6 | fd9305df | 6b1eb212 | 502 | 1789239528 |
| 2 | hits3 | efeff7cf | a1a996d7 | 4d94f48d | 2fce8ef7 | 31409094 | 502 | 1789239801 |
| 3 | hits3+23770 | 80a1a2a3 | f130b52c | bc0298ec | 91c2972e | 6b157640 | 529 | 1789239801 |
| 4 | hits4 | 60fbd95c | 63bdf702 | 4366c534 | 71504ea5 | 2ecacaaf | 360 | 1789240076 |
| 5 | hits5 | 75c92396 | 3bf5db6a | 5532d586 | 5bde8d35 | 115c5f98 | 360 | 1789240229 |
| 6 | hits6 | f364ab44 | cf53ebca | b80bc6a4 | 9565b3ea | 5969896a | 360 | 1789240340 |
| 7 = S0 | hits7 | 13271271 | db50f44c | b63798cc | dab7f51a | fb1a8296 | 360 | 1789240512 |
| 8 = S1 | hits7+22272 | aa447d3c | 2ec65f51 | efdf3cd8 | 8c568829 | 7c933329 | 387 | 1789240512 |
| 9 = S2 | hits7+28663 | f1a55b5b | 9949bda6 | 011d4d1e | 13227bce | 4bce691e | 360 | 1789240512 |

sec recovered from claims' created_at (+1 s law); row 7/8/9 seconds match
desc_det's explicit `sec=1789240512`, and fin_descs' #0/#2/#4/#7/#10 for signing
A are byte-identical to row 7 (cross-validates both parse paths).

**Wire-body layout verdict (task's "locate fad0f10d / bfffffff")**: they are NOT
there. 0 hits for all 24 needles (incl. the full #9/#8 constants, screen dwords,
ASCII numbers, property strings) in any of the 13 wire blobs at any byte offset,
both endiannesses. The task's section order (36+1+8+5+4+1+claims+2 = 55+ dwords)
cannot fit the 44-dword body anyway. The wire body is the whitened 176-B VM
output; the section structure exists only in the region/ctx (which is what the
147-dword descriptor list feeds the VM).

## 2. NEW-INPUT correlations (widthPixels/heightPixels/props) — ALL NEGATIVE

- **#2 is NOT the raw JNI int.** The two GetIntField reads are
  `widthPixels`→ctx+0x60, `heightPixels`→ctx+0x64 (jni_names.md), i.e. constant
  1080 / 2237 per device — yet region #2 varies per call with everything else
  fixed (same second + same claims: S0 `fb1a8296` vs S2 `4bce691e`; rows 2/3
  same second: `31409094` vs `6b157640`). No window of d2/d0/d4 equals
  1080/2237/2400/31/420/53 raw, byte-swapped, or as 16-bit halves (0 hits over
  10 rows). d2^W0, d2^U[k], d2^hdrword[j], d2^sec: row-unique in every
  combination (10 distinct values over 10 unique rows each). Java side
  corroborates: modCount=49, size=53 — **constant** across all 3 fresh signings,
  so no Java-visible int can supply d2's variation.
- **#4**: first dwords are small-bitfield-like (`00028002 800a4008 …`,
  `00100004 000c0800 …`); 4-byte windows match NO window of `motorola`,
  `moto g42`, `S2SE32.28-28-4`, `arm64-v8a`, `android12`, `com.penti.app`,
  `com.android.vending`, `jut9tib0eeps`, `android5.7.0`, `production`,
  `service`, `phone`, `adj9` (0 hits, 13 strings × 10 rows). No
  d4[k]^claims-window is constant across rows (scan k×356 offsets: 0).
- **Wire blobs vs new inputs**: no 4-B window of H (29 windows × 2 orders,
  chance 2.4e-6/blob), canon, package, device strings or screen dwords appears
  in any blob. Consistent with S1_FULL_DECODE's "H never raw-contained".
- **tile ^ canon / tile ^ H[:16] / W0 ^ header(second)**: not testable on the
  wire (tile/W0 not extractable — body whitened); the body-level equivalents
  were run instead and are all non-constant (§3).

## 3. PER-CALL SEED ISOLATION — the money section

### 3.1 Fresh pairwise XOR (3 signings share device/props/claims-shape; differ in canon content, H, second)

| pair | Δsec | body bytes differing (of 176) | body dwords nonzero (of 44) |
|------|------|------|------|
| 1~2 | 66 | 175 | 44 |
| 1~3 | 86 | 174 | 44 |
| 2~3 | 20 | 176 | 44 |

Dictionary membership for every body-XOR dword — tested against
{H_i[a]^H_j[a] (all aligned a, both byte orders), canon_i[a]^canon_j[a] for ALL
~1200 offsets, header-word XORs, sec delta, sec XOR, ms delta}: **0 hits**
(chance per battery ≈ 44×1150/2³² ≈ 1.2e-5). Lag-structure of the XOR
(lags 1..128, byte and dword): at chance (3–6 equalities, chance ≈ 4.5).

### 3.2 Constant-XOR-across-signings tests (fresh 3)

`body ^ H[:16]`, `body ^ H-repeated`, `body ^ canon[:176]`,
`body ^ header-repeated`, `body ^ H[16:] repeated`, `body ^ header-dword-stream`:
for each candidate keystream the pairwise differences differ for every pair →
**no constant term exists**; likewise position scans
{body_i[k] ^ H_i[j]} over 44×8 and {body_i[k] ^ canon_i[a]} over 44×1219 and
{body_i[k] ^ sec/ts}: **zero singleton values**.

### 3.3 The decisive instrument: the oracle probe (same-process controlled re-signing)

Semantics verified in `Hook.java::oracleSuite`: fresh `LinkedHashMap` clone +
`h.clone()` on EVERY call (the earlier "per-call randomness" mis-read is fixed);
variants: A1/A2 = identical inputs; B1/B2 = identical with H:=0; C1 = H[0]^=1;
D1/D2 = first map value `gps_adid_attempt` 1→"1X"; E1 = level 30; F1 = level 31.

| blob | sec (inverted) | note |
|------|-----|------|
| real | 1790106110 | == fresh1 |
| A1 / A2 | 1790106113 / 1790106114 | identical inputs, 1 s apart |
| B1 / B2 | 1790106116 / **1790106116** | H=0; **identical 16-B headers** |
| C1 | 1790106117 | H bit flip |
| D1 | 1790106118 | map value +X |
| D2 / E1 | 1790106119 / **1790106119** | **identical headers**, different inputs |
| F1 | 1790106120 | level 31 |

Byte-diff counts (of 192, incl. header):

```
B1~B2  same inputs (H=0), SAME second   n_diff=175  first=16   <- header identical
D2~E1  same second, different inputs    n_diff=174
A1~A2  same inputs, different second    n_diff=191
A1~B1 / A1~C1 / A1~D1 / A1~E1 / A1~F1   n_diff=190..192
```

**B1~B2 is the proof**: map content, H (zeroed), level AND second all identical
→ the 176-B body still differs in 175/176 bytes (the one equal byte, body
offset 2, is chance: expectation 0.69). The body is therefore a function of
(second, descriptors) where the **descriptors themselves carry per-call
entropy** that is neither the header PRNG (same second → same header, and the
body does NOT continue the srand stream: B1/B2 body dwords have no membership in
Random3(sec) draws 9..400 raw or XOR-paired) nor any of (map, H, level).
A consequence: byte-level input-sensitivity measurement (the probe's original
purpose) is saturated — every input flip is indistinguishable from per-call
noise (190–192/192 diffs), consistent with ORACLE_FINDINGS "the body
re-randomizes on every call".

### 3.4 Region same-second pairs (pure per-call differences, descriptor level)

- **S0~S2**: same sec 1789240512, claims byte-identical (360 B, hence same
  canonical → same TEE H):
  `W0^W0=e282492a  X^X=421949ea  U^U=b72ad5d2 c9958ed4 9692f46a e82dab6d
   d2^d2=b0d4eb88  d4^d4=00000480 04a440a8 a098c47c 8010469d 20b042f3 c6500401 21b87ebf 1c47aa65`
  Only d4[0] moves by a small flag-like delta (0x0400 vs 0x0080, diff 0x0480);
  everything else full-word. (For the same-second different-claims pairs
  old2~old3 and old7~old8, d4[0] also differs full-word.)
- So the per-call entropy reaches #0 (W0, X, tile), #2 and #4[1..7].

## 4. THE constant (positive finding of this run)

**U[2] ^ U[0] == R‖R** — i.e. the two 16-bit halves of `tile[2]^tile[0]` are
EQUAL — holds **13/13 region rows**:

```
R = 1962 324e 8e67 60f2 12ed 602b 5a36 01e7 a290 205f (10 unique / 10 unique rows)
controls: U[3]^U[1] R||R: 0/13 ; W0^X R||R: 0/13  (chance 13/65536)
```

This is the same law `rev/all_laws.json` recorded as its ONLY constant on the
older 16-row corpus (`(T3^T1) - R||R == 0`, their T1/T3 = words 2/4). It is now
confirmed on an independent parse + corpus. Meaning: the per-call tile is
NOT uniform — its generator leaves a 16-bit replication fingerprint (R itself
is per-call: same-second rows 7/8/9 have R = 01e7/a290/205f). Any offline model
of the #0 fill must reproduce this relation; it is the first crack in WALL A's
per-call entropy.

## 5. Time correlation & PRNG kinship — ALL NEGATIVE (precise)

- seconds recovered (fresh): 1790106110 → 1790106176 → 1790106196; gaps 66 s /
  20 s == ts gaps 66.0 s / 19.7 s (task's "66 s and 19 s").
- W0 / X / tile / d2 ∈ Random3(seed) draws 1..600 (raw draws, XOR-pair
  d[2i]^d[2i+1], adjacent d[i]^d[i+1]) for seeds ∈ {sec, W0, X, d2}: **no
  membership, all 13 rows** → the region per-call words do NOT continue the
  header PRNG stream.
- consecutive-W0 kinship (10 unique rows, gaps 111–273 s): Park-Miller step
  `(16807·W0) mod (2³¹−1)`: false for every pair; xorshift32: false; LCG solved
  from 3 points fails on the rest (mod 2³²: a=5fc80ca7 c=893ab9af; mod 2³¹−1:
  a=48f147e4 c=7a90927f — both non-holding); W0 linear in sec (exact, both
  moduli): false; W0^hdrword row-unique (40/40).
- counter hypotheses W0_{n+1}=f(W0_n) (PM/LCG/xorshift/small affine): none hold.
- body-dword MSB: 23/44, 19/44, 24/44 below 0x80 → body words are full 32-bit
  (unlike the 31-bit header draws) — the body is not raw rand() output.

## 6. Seed-model ranking (evidence-weighted)

1. **Header = Random3(srand(time(NULL))), 8 draws, XOR-paired, BE** —
   CONFIRMED 13/13 unique inversions, MSB 4/4, created_at+1 law holds on both
   corpora. Fully offline-forgeable.
2. **Body = deterministic VM merge of the 147 descriptor dwords, seeded by the
   second** — CONFIRMED for signing A (prior fin_result 44/44 exit-clean).
   Combined with §3.3: the per-call entropy lives in the DESCRIPTOR FILL
   (`sub_8d6f4`/`sub_9afa4`/the ctx int+byte[] paths), NOT in the merge VM.
3. **Per-call source = process-local state read during fill.** Excluded
   explicitly: time(NULL) second (B1~B2), srand-stream continuation (§5),
   H/claims/level/screen (S0~S2, B1~B2, fresh pairs), Java int fields
   (modCount/size constant), previous-W0 counters (§5). Remaining candidates,
   all invisible to the oracle's input controls: (a) ART identity hashCodes of
   the per-call objects (each call gets a fresh `LinkedHashMap` clone — the
   oracle always clones; ART identity hashes are per-object PRNG output;
   nsign_in logs them: `@2fe8555`, `@a4512f`, `@5dc55e1`); (b) native heap
   pointers/ASLR consumed via the documented uninitialized-read paths
   (fin_result's LENQ heap-tail reads); (c) a second clock read
   (nanotime/monotonic) inside `sub_8d6f4`. Ranking (a) ≈ (b) > (c): the fill
   path demonstrably reads Java object state over JNI, and the oracle's
   fresh-clone-per-call design guarantees new identity hashcodes per call,
   which is exactly the observed "everything else identical, all per-call
   words move" signature.
4. **Exploitable regularity**: the U[2]^U[0] == R‖R tile law (§4) constrains
   the generator; R (16 bits/call) is the first per-call quantity small enough
   to brute-force against once the generator family is guessed.

## 7. Negative results (stated precisely)

- No descriptor constant (#9, #8), no H window, no canonical window, no
  package/device/prop string window, no screen/level/dpi dword appears in any
  of the 13 wire blobs (all offsets, both endiannesses).
- No constant-XOR component across the 3 fresh signings for any tested
  keystream (H, canon, header, sec) at any of the 44 body positions
  (position scans and whole-body tests both empty).
- No body-XOR dword equals any H^H / canon^canon / header-word / sec-delta
  value (dictionary scans, chance ≈ 1e-5 per battery).
- No Random3-stream continuation into the region words (4 seeds × 600 draws ×
  3 pairing schemes).
- No PM/LCG/xorshift/affine/counter kinship between consecutive W0s, and no
  W0-vs-second linear law (both moduli).
- d2 shows no relation to widthPixels/heightPixels/2400/level/dpi/mapsize in
  any raw/XOR/halfword form, despite being per-call; the JNI ints and
  modCount/size are constant per device/process and cannot produce d2's
  variation.
- Byte-level input sensitivity of the body is unmeasurable from wire diffs:
  per-call whitening noise (≥174/176 bytes) saturates every input flip
  (H=0, H bit-flip, map value, API level).
- tile^canon and tile^H[:16] constancy: not testable on the wire corpus
  (tile is not in the wire blob); the equivalent body-level tests are negative.

## 8. Files / repro

- `rev/corpus_seed.py` — everything above in one runnable script (paths absolute).
- `rev/corpus_seed.log` — full output (275 lines).
- Inputs: `device/java_dump/signings_extract.json`,
  `device/java_dump/adj9_capture_run1.log` (probe block),
  `rev/all_signings.json`, `rev/desc_det_result.json`,
  `rev/header_gen.py` (imported, unmodified), `rev/fin_descs.json` (cross-check).
