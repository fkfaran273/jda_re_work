# fresh3 — the fresh-3 corpus: srand operand verdict, corpus parse, and the ANSI-LCG / TYPE_3 / lrand48 pair-XOR sweep

Date: 2026-09-23. Pure offline python (`rev/fresh3.py`, full output `rev/fresh3.log`,
machine-readable `rev/fresh3_result.json`). READ-first inputs honored:
`corpus_seed.md` (section map + laws), `WALL_A_SLICE_146.md`, `l48_sweep.md`,
`state_walk.md`. Corpus: `device/java_dump/signings_extract.json` (3 fresh
signings), `rev/all_signings.json` (10 region rows), `rev/pair_h3.json` (row
seconds), `rev/header_gen.py` (imported unmodified).

---

## 0. TL;DR

1. **srand operand VERDICT (disasm): `srand(time(NULL))` VERBATIM.** At the sole
   srand call site, `bl time` @0x12cbbc is followed by `bl srand` @0x12cbc0 with
   **zero intervening instructions** — x0 at srand IS the raw time(NULL) return.
   The urandom→seed chain (`bl 0x143794` @0xdb160 inside nOnResume 0xda4b0..0xdb1c8)
   is a **parallel, separate seeding path**: 0x143794 = get8random(0x13e0e4) →
   `bl 0x1437ec(state, urandom_word)`, and 0x1437ec calls only local helpers
   (0x13e030/0x143c88/0x13dfd0/0x144074/0x143d98) — it **never calls PLT srand
   (0x148d30)**. The wire builder's libc rand() stream is therefore seeded by the
   RESUME WALL-CLOCK SECOND, not anything urandom-derived.
2. **Corpus parse:** the fresh 192-B blob = 16-B header + 176-B body (44 dwords).
   The known constants (#9 = cert SHA-1 `fad0f10d…`, #8 = `bfffffff…`, screen
   ints, and all other needles) appear **nowhere verbatim** (0 hits, any offset,
   both endiannesses); the bodies have **zero internal repetition** (unlike the
   pre-whitening #0 tile, which repeats U 8×) and are full-32-bit. ⇒ the body is
   the **whitened VM output**; W0/tile/d2/d4 are NOT extractable from the fresh
   bodies (d2 "else skip" branch taken), exactly as corpus_seed.md §1 concluded.
   The sweep therefore targets the REGION descriptors (all_signings.json), whose
   layout law was re-verified on all 10 rows.
3. **Header law re-verified (task 2):** `make_header(second)` matches each fresh
   blob's first 16 B with a UNIQUE hit: **1790106110 / 1790106176 / 1790106196**
   (±10 s window). Harness: header words == pair-units k=0..3 of
   `Random3(sec)` — True for all 3 fresh + all 8 pair_h3 blobs. Also found and
   fixed a corpus inconsistency: pair_h3's seconds are the header-inverted ones;
   corpus_seed.md's created_at-derived values for rows 2/3 (1789239801) do NOT
   match the blob headers (1789240075/76) — header law wins.
4. **THE SWEEP — PRECISE ZERO.** 3 streams (bionic `lrand48`, **ANSI-LCG
   1103515245x+12345 mod 2^31 — first time ever tested**, bionic `random()`
   TYPE_3 = header_gen.Random3 — also first time at scale) × 64 seeds (every
   row's second−3..+3, plus the shared single-resume roots 1789240512±3 and
   1790106110±3) × units {raw draw, pair r_k^r_{k+1}, triple
   r_k^r_{k+1}^r_{k+2}} × pre-advance k = 0..2,000,000: **15 attributed hits vs
   15.6 expected from chance alone; max same-(stream,seed) cluster = 2** (a real
   signing would cluster 10–16 units in one seed); cross-row continuation
   ordering absent. **NO stream is alive**: neither lrand48, nor the ANSI-LCG,
   nor TYPE_3 explains ANY word at ANY position ≤2M draws. The one historical
   anchor (row 7 W0, lrand48 pair) reproduced at exactly its known k and remains
   the isolated ~1/200 noise event l48_sweep.md already classified.

---

## 1. srand operand — the disassembly (task 0)

PLT (plt_lookup.log): `0x148d10=rand 0x148d20=time 0x148d30=srand
0x148a10=__stack_chk_fail`; `0x13e0e4` = get8random (the library's only
/dev/urandom reader).

### 1.1 The srand site (0x12cb74, called from nOnResume @0xdafe4)

```
0x12cbbc  bl  0x148d20      ; time()
0x12cbc0  bl  0x148d30      ; srand(x0)   <- x0 = time(NULL), NOTHING in between
0x12cbd8  bl  0x147d3c      ; descriptor maker (calloc-style node, 0x90 bytes)
```

Zero intervening instructions between the two `bl`s: no register write, no
branch. The whole flattened body head (0x12cb74..0x12ce60) contains only these
three `bl`s + hub dispatches (`b.eq`). **No call to 0x143794 anywhere in the
function's straight-line head; nothing can modify x0 between time and srand.**

### 1.2 The urandom chain is a different, parallel path

```
nOnResume (0xda4b0..0xdb1c8, hub 0xdaad0):
  0xdafe4  bl 0x12cb74            ; -> srand(time(NULL)) + pre-create #0 (0x90 B)
  0xdb160  bl 0x143794            ; -> urandom seeding of a SEPARATE state object
0x143794(x0=state):
  bl 0x13e0e4 (get8random, 8 bytes to stack) -> w1 = first urandom word
  bl 0x1437ec(x0=state, w1)       ; seeds the caller's OWN object
0x1437ec: stores w1 at [state], then bl 0x13e030 / 0x143c88 / 0x13dfd0 /
          0x144074 / 0x143d98 — LOCAL helpers only; the 64-bit mov/movk
          constant blocks (0xC8D50CEBBDC8DF4A, 0x8F3DF23EFF64B7CC, …) are its
          own multiplier schedule. It NEVER calls PLT srand or time.
```

So even though both fire at RESUME, the urandom→(LCM-multiplier)→state chain
cannot feed srand's operand, and it does not touch libc's rand state.

**⇒ Wire-builder rand() stream seed = the resume wall-clock second (time(NULL)),
verbatim.** (Which still leaves the stream POSITION unknown — resume-second ≠
signing-second, and unknown consumers — which is what the sweep probes.)

### 1.3 The pair-XOR opcode (for the record)

Loop 0x12a2f8..0x12a414 (back-edge `cbnz` @0x12a414 after `bl 0x146650`):
per iteration exactly `bl rand` @0x12a2fc → push(0x147630) → `bl rand`
@0x12a31c → push → pop(0x147734) ×2 → `eor w2,w0,w21` @0x12a368 → push; then
dup-over(0x14784c,w2=1), pop ×2, emit `bl 0x146ed8`. Small-integer pushes
interleave between iterations (0x14 @0x12a434 = 20 B = #9's size; `add w2,w0,#1`
@0x12a3f4). So the whitening unit is the **non-overlap pair d[2j]^d[2j+1]** —
sliding pairs (tested here) are a strict superset of those (they sit at even k).

## 2. Fresh-3 corpus parse (task 1)

### 2.1 Blob anatomy and the constant search

`signings_extract.json`: 3 signings, blob 384 hex = 192 B = 16-B header + 176-B
body (44 BE dwords). Verbatim needle search over the full blob, ANY byte offset,
BE and LE:

| needle | hits (3 blobs) |
|---|---|
| #9 `fad0f10d 60f93c17 937b2f1e b6c09691 ae7d74bd` | **0** |
| #8 `bfffffff fffffd1f 00070000 00000000` | **0** |
| 1080 / 2237 / 2400 / 420 / 31 / 53 (BE and LE) | **0** |

(cross-check: SHA-1 of `rev/cert_signer1.der` = `fad0f10d…` = the #9 constant —
True.) Body structure per signing: **44/44 distinct dwords, 0 duplicates, 0
period-4 repeats, 0 consecutive repeats; bit31==0 in 23/44, 19/44, 24/44**
(full 32-bit words). Pairwise body diffs 175/174/176 of 176 bytes (re-confirmed).

**Layout verdict:** the constants are NOT visible verbatim ⇒ the body is
whitened (there is no per-call word layout to recover from the fresh blobs — the
whitening is position-dependent, consistent with an advancing rand mix: the
pre-whitening #0 tile repeats U 8×, the whitened body never repeats). Per the
task's "else skip" branch, d2 and friends are taken from the REGION corpus.

### 2.2 Region descriptor layout re-verified (all_signings.json, 10 rows)

```
#0 (36 dw) = W0 | X | U0 U1 U2 U3 ×8 | U0 U1      (asserted all 10 rows)
#2 = d2 (1 dw);  #4 = 8 dw;  #5 = #6 = 00000000 (10/10)
#8/#9 constants present in 10/10 rows
X == U3 in 9/10 (row 9 = S2, the known exception)
U[2]^U[0] == R‖R in 10/10  (R = 1962 324e 8e67 60f2 12ed 602b 5a36 01e7 a290 205f)
```

## 3. Header re-verification (task 2)

`make_header(sec)` (header_gen.Random3, TYPE_3 additive-feedback, 8 draws,
XOR-paired, BE) vs blob[0:16]:

| signing | ts (ms) | sec (unique hit in ts/1000 ± 10) | header |
|---|---|---|---|
| fresh1 | 1790106110175 | **1790106110** | 4efd72e6 33bbc54a 45c8e70f 10e63a5c |
| fresh2 | 1790106176174 | **1790106176** | 03bd3d9f 7fc91f7a 0c43c2f3 7e140f74 |
| fresh3 | 1790106195890 | **1790106196** | 3199cac6 753d466b 722eec0a 6f5ea925 |

Harness (now proven, not assumed): **header words == pair-units k=0..3 of
Random3(sec)** — True for all 3 fresh blobs and all 8 pair_h3 blobs (unique
inversion in ts/1000±15 each). Note: pair_h3's `second` fields ARE the
header-inverted seconds (all 8 re-verified here); corpus_seed.md's table rows
2/3 carry created_at-derived seconds (1789239801) that contradict the blob
headers (1789240075/76) — header law wins; the sweep uses header-verified
seconds. Rows 8/9 (S1/S2): sec = 1789240512 per desc_det_result.json (explicit)
+ corpus_seed.md; all_signings rows carry no wire blob, so no re-inversion
possible there.

## 4. THE SWEEP (task 3) — design

**Model under test:** once per resume, `srand(S)`; the wire builder draws the
advancing stream; word = raw draw, or pair-XOR unit r_k^r_{k+1}, or triple
r_k^r_{k+1}^r_{k+2}, at pre-advance k ≤ 2,000,000.

* **Streams (3):** `lrand48` (srand48: x=(s<<16)|0x330E; x=0x5DEECE66D·x+0xB mod
  2^48, out=x>>17 — all prior sweeps used only this);
  **ANSI-LCG** (x=1103515245·x+12345 mod 2^31, srand=s; advance-then-output —
  **never tested before by anyone**; the no-pre-advance output convention is
  covered by 3 extra units/seed: raw seed, seed^out0, seed^out0^out1);
  **TYPE_3 random()** (bionic rand = header_gen.Random3 — the header's own
  generator; only tested to 600 draws before, now to 2M). All three steppers
  validated against scalar references; TYPE_3 additionally by the header
  identity (§3).
* **Seeds (64 unique):** for every row, its header-verified second −3..+3
  (region rows from pair_h3 + rows 8/9 = 1789240512; fresh rows 1790106110/176/
  196) — covering both the sec and sec±1 conventions — PLUS the shared
  single-resume roots: 1789240512±3 tested against ALL 10 region rows
  (re-runs l48_pairs pass C's cross-continuation idea with the two new streams)
  and 1790106110±3 (sec_0) tested against ALL 3 fresh rows.
* **Targets:** region per-call words W0, X, U0..U3, d2, d4[0..7] per row
  (13/row) + fresh body dwords 44 BE per fresh signing (the only fresh words
  that exist). 273 unique values, **157 pxable (bit31==0)** — words with bit31=1
  are structurally impossible for pure XOR units of any 31-bit stream and can
  never hit.
* **Units:** raw draw, sliding pair d[k]^d[k+1] (superset of the opcode's
  non-overlap d[2j]^d[2j+1]), sliding triple d[k]^d[k+1]^d[k+2]; k = 0..2,000,000
  (draw index).
* Attribution: seed s is only credited with hits on words of rows it was drawn
  for (the attributed-cell test). Hits against other rows' words are counted
  separately as cross coincidences.

### Chance baseline (stated, per the task)

Chance per unit-vs-target comparison = |pxable targets|/2^31. Per seed:
6,000,006 units (raw 2,000,003 + pair 2,000,002 + triple 2,000,001). Over the
154 attributed (seed→rows) cells and their pxable targets:
**expected ≈ 5.20 noise hits PER STREAM (≈ 15.6 over the 3 streams)**. Cross
(union-of-all-273-targets) coincidences: expected ≈ 28.1/stream.

## 5. THE SWEEP — results

### 5.1 Attributed hits (complete table)

| # | stream | form | seed | k (draw idx) | value | word(s) |
|---|---|---|---|---|---|---|
| 1 | lrand48 | pair | 1789240225 | 902263 | 00040010 | reg5.d4[0] |
| 2 | lrand48 | pair | 1789240512 | 214220 | 13271271 | reg7.W0 — **THE ANCHOR** (known noise) |
| 3 | lrand48 | triple | 1789240515 | 896554 | 75c92396 | reg5.W0 |
| 4 | ANSI | raw | 1789240514 | 43827 | 4bce691e | reg9.d2 |
| 5 | ANSI | raw | 1790106176 | 43531 | 6cbc0904 | fresh2.dwBE[16] |
| 6 | ANSI | raw | 1790106198 | 9184 | 74bac837 | fresh3.dwBE[9] |
| 7 | ANSI | pair | 1789240510 | 1780519 | 02000001 | reg2.d4[0] |
| 8 | TYPE3 | raw | 1789239528 | 85126 | 1a401670 | reg1.d4[4] |
| 9 | TYPE3 | pair | 1789239529 | 397215 | 63a9ace8 | reg1.U2 |
| 10 | TYPE3 | pair | 1789240075 | 375075 | 4d94f48d | reg2.U0 |
| 11 | TYPE3 | pair | 1789240230 | 563474 | 1008401c | reg5.d4[2] |
| 12 | TYPE3 | pair | 1790106111 | 280246 | 053b61a3 | fresh3.dwBE[24] |
| 13 | TYPE3 | pair | 1790106112 | 1775571 | 7d112a7b | fresh2.dwBE[27] |
| 14 | TYPE3 | triple | 1790106108 | 208980 | 7d112a7b | fresh2.dwBE[27] |
| 15 | TYPE3 | triple | 1790106111 | 780634 | 493b6a6a | fresh3.dwBE[2] |

Per-stream totals vs expectation: lrand48 3, ANSI 4, TYPE3 8 — expected 5.20
each; **total 15 vs 15.6**. Cross (unattributed) coincidences: 25 / 16 / 27 vs
28.1 expected — on the chance line.

### 5.2 Discriminators — all say NOISE

* **No clustering:** max hits sharing one (stream, seed) = **2**, and that tie
  is (TYPE3, seed 1790106110+1): two INDEPENDENT units — different words
  (fresh3.dwBE[24] vs fresh3.dwBE[2]), different forms (pair vs triple), k
  280,246 vs 780,634. (The double value 7d112a7b, hits #13/#14, is across two
  different seeds and forms — also coincidence.) A real signing would cluster
  ~10–16 units of one row inside ONE seed at adjacent/ordered k.
* **No cross-row ordering:** rows 7/8/9 (one process, same second) show no
  monotone k progression (row 8/9 words don't follow row 7's anchor at all);
  fresh 1→2→3 unordered likewise.
* **The anchor reproduced, nothing around it:** hit #2 is exactly
  lrand48(1789240512) draws 214220^214221 = reg7.W0 (their non-overlap pair
  j=107110) — the known ~1/200 noise event of l48_sweep.md. Its discriminating
  predictions (row 7's other units nearby, rows 8/9 continuing) remain falsified:
  rows 8/9 have ZERO lrand48 hits in this run.
* Every stream sits on its expectation; no stream is above chance.

### 5.3 Verdict

**PRECISE ZERO.** With srand operand = time(NULL) (the disasm verdict), the
region per-call words (W0, X, tile U0..U3, d2, d4) and the fresh whitened body
dwords are NOT raw draws, pair-XOR units, or triple-XOR units of ANY of the
three candidate libc rand() streams — lrand48, the ANSI-LCG (1103515245x+12345
mod 2^31, tested here for the first time), or bionic random() TYPE_3 (the
header's own generator, first time at 2M scale) — for ANY seed
second−3..+3 (including the shared-resume roots 1789240512 and 1790106110), at
ANY stream position k ≤ 2,000,000. 15 hits vs 15.6 expected: the hits are the
chance baseline itself, with zero structure. **No stream is alive.**

Consequence (consistent with l48_sweep.md and corpus_seed.md §6): if the
wire-builder's pair-XOR opcode is on the signing path at all, its draws are
either consumed at stream positions beyond 2M per resume, or the seed is not
the resume second (or not time at all — but the disasm pins srand's operand),
or — most likely — the per-call words are dominated by the process-local
entropy in descriptor fill (sub_8d6f4/sub_9afa4) with the rand-pair values only
a minor/indirect input. The decisive instrument remains the logged-rand
emulation of a live signing.

## 6. Files / repro

* `rev/fresh3.py` — everything above in one runnable script (numpy-vectorized
  across seeds; capstone disasm inline; paths absolute).
* `rev/fresh3.log` — full output. `rev/fresh3_result.json` — machine-readable.
* Inputs: `device/java_dump/signings_extract.json`, `rev/all_signings.json`,
  `rev/pair_h3.json`, `rev/desc_det_result.json`, `rev/header_gen.py`,
  `rev/cert_signer1.der`, `extracted/arm64/lib/arm64-v8a/libsigner.so`,
  `rev/plt_lookup.log`.
