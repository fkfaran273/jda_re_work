# l48 sweep results

(`l48_sweep.py` simple-mix sweep: NEGATIVE, recorded in WALL_A_SLICE_146 §5.
This file collects the follow-up sweeps; the pair-XOR validation below is the
decisive one for the static pin of the rand opcode.)

## Pair-XOR validation

Date: 2026-09-23. Script `rev/l48_pairs.py` (full output `rev/l48_pairs.log`,
wall 235 s). Model under test: `srand48(resume_second)` once per nOnResume,
wire word = XOR of consecutive lrand48 draws — the statically proven unit
`d[2j] ^ d[2j+1]` (loop 0x12a2f8..0x12a414, `eor w2,w0,w21` @0x12a368) plus
the overlapping/skip/triple/quad/chain supersets, and `pair ^ C` with C from
the 678-entry POOL32 (mov/movk chains of sub_9afa4 union rand-block region
0x12a200..0x12a500 — the block itself has NO mix constant).

### Pass 0 — anchor (re-verified)

row 7 W0 = 0x13271271 = d[214220] ^ d[214221] under srand48(1789240512)
(= the row's own second), pair k=107110. Chance for the orchestrator's exact
test (rows 7/8/9 x 25 pxable words x 400k pairs): 0.0047 hits, i.e. the anchor
is a ~1/200 event on its own. The passes below are the discrimination.

### Hits table (every hit found, classified)

| pass | row | word | val | seed / off | k (pair index unless noted) | form | class |
|---|---|---|---|---|---|---|---|
| 0/A/B/C | 7 | W0 | 13271271 | 1789240512 / off=0 | 107110 (draws 214220/214221) | pair (g=1) | THE ANCHOR — the ONLY pure hit anywhere |
| A | 5 | d4[5] | 661a3674 | 1789240179 / off=49 | 3513 pair = 7026 adj (same draws 14052/14053) | pair+adj self-overlap | detector artifact, 1 real hit |
| A | 8 | T2 | 4d4f9e48 | 1789240512 / off=0 | draw 273147 | sk1 | noise (isolated) |
| C | 8 | d2 | 7c933329 | 1789240512 | draw 5089469 | sk1 | noise (not the proven form) |
| C | 9 | d2 | 4bce691e | 1789240512 | draw 2874743 | adj | noise (not the proven form) |
| B | — | 23 pxor^C hits incl. 2-word g=84 pair (X|T3 @196292, d4[1] @202518, different C) | | 1789240512 | scattered | pair^C | noise (exp 21.0) |
| D | fresh n=1..3 | 15 body-dword hits (dw3/LE t4, dw15 sk1, dw8 chain, ...) | | 1790106110..107 / sec-0..-3 | 0.35M..3.9M | mixed | noise (exp 9.2, no cluster/order/word-consistency) |

Aggregate pass A over all 6010 cells (rows 0..9 x seeds second-0..-600 x 2M
draws): pure 275 (chance expectation 305.6); pxor^C 15276 (expectation
15281.9) — both ON the chance line. Max pure hits in any one cell: 1 unique
(a REAL signing should cluster ~10-16 units in one cell). Cross-row same-seed
groups: 16, all chance-level (the seed=1789240512 rows[7,8] group is the
anchor + one noise hit, "ordered" by coin flip).

### Pass B — stride scan: NO g0 exists

Seed 1789240512, draws 194220..234220 (+g up to +256), ALL row-7 words, pure
+ pxor^C. Expected pure chance 0.03. Result: exactly ONE pure hit — the anchor
itself at g=1, k'=214220. No other gap g in 1..256 produces any pure hit for
any row-7 word; no multi-word same-g structure except a chance C-pair at g=84.
If the builder consumed d[k']^d[k'+g] with any stride other than 1, or row 7's
other pxable words (d4[0], d4[1], d4[4], d4[6], d4[7]) were pair units near the
anchor, they would appear here — they do not. **No gap g0; no opcode pattern.**

### Pass C — cross-signing: rows 8/9 do NOT continue the stream

Seed 1789240512, 10M draws = 5M pairs (rows 7/8/9 are one process, same
second, consecutive nsign_ts +22272/+28663 ms). Full-range pure: row 7 = the
anchor only (its pair-form listing in the log is the same event — drawk 107110
is the pair INDEX, draws 214220/214221); row 8 = 2 hits, row 9 = 1 hit, all in
superset forms (sk1/adj), scattered, expectation 0.14+0.14+0.30. **Ordering
test 7<8<9: FAILED** (row 8's d2 at pair 2544734 sits after row 9's at
1437371). pxor^C full-range: 100/114/176 vs chance 102.8/102.8/160.9; tight
clusters at chance. Prioritized windows pair [107110..117110] (task spec,
re-scanned explicitly): exactly ONE hit total — the anchor (W0, C=0, k=107110);
**rows 8/9: 0 hits, pure and C-family, expected 0.02 if the model were real.**
A real continuation would put rows 8/9's 10 pxable words within a few thousand
pairs after 107110.

### Pass D — fresh-3: chance

`device/java_dump/signings_extract.json`: the task's section map (d0 36dw +
#2 + #4 + #7 = 46+ dwords) OVERFLOWS the 44-dword body, and 0 needle hits
(#9/#8 constants, screen ints, H-windows) — re-confirming corpus_seed.md §1:
descriptors are NOT in the wire body. Tested anyway: all 44 body dwords
(BE+LE), seeds 1790106110-0..-3 per signing AND single-resume shared-stream,
4M draws, all forms: 15 pure hits vs expectation 9.2, all isolated singletons
across random seeds/words/forms/positions, no cluster, no n=1→2→3 ordering,
none in the proven pair form at consistent offsets.

### Verdict: NOISE

The pair-XOR model — pure, stride, or pair^C(POOL32) — is **disproven as the
generator of the region words**. The row-7 anchor is a coincidental ~1/200
hit: every discriminating prediction it implied (row 7's other units nearby,
a stride structure, rows 8/9 continuing the stream at increasing k, clustered
cells at the true off, structured pxor^C cells) is falsified. The static pin
stands (the wire-builder opcode IS pair-XOR of two rand draws), but the draws
that feed it for a real signing are not `lrand48` after `srand48(signing
second)` at any recoverable position ≤10M draws — consistent with the rand
sites being consumed by a different data path than the region words, and/or
with corpus_seed.md §6's per-call process-local entropy in descriptor fill
(`sub_8d6f4`/`sub_9afa4`) that dominates the wire. Next lever if revisited:
logged-rand emulation of a live signing (quota-blocked per SLICE 146 §5) to
observe the actual draw stream, rather than offline sweeps.

Files: `rev/l48_pairs.py`, `rev/l48_pairs.log` (complete rerun, 2026-09-23).
