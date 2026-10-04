# vm_activation — the rand-stream position SOLVED: 8 draws per signing, at position 0, header only

Date: 2026-09-23. Static call-graph + instrumented full-program execution.
Tools: `rev/vm_sim.py` (extended: `full` / `dclaims` drivers), `rev/vm_act_run.py`
(+ `vm_act_run.log`), `rev/fin_vm2.py` FinEx (the byte-exact executor,
`fin_result.md`), `rev/scan_rand.py`, `rev/header_gen.py`. Library:
`extracted/arm64/lib/arm64-v8a/libsigner.so`.

---

## 0. Headline — the contradiction resolves AGAINST the premise

The premise "the region words ARE pair-XOR of rand draws" was a misreading of
the static evidence. The full-program facts:

1. **The interpreter runs ONCE PER nOnResume, immediately after srand.**
   `bl 0x100094` has exactly ONE site (0x12d39c) in the whole library, and it
   lives inside the flattened function **0x12cb74..0x12de60** — whose ONLY
   caller is `bl` at **0xdafe4** inside the JNI export
   `Java_..._NativeLibHelper_nOnResume` (0xda4b0; confirmed via .dynsym). The
   same invocation calls `bl time` @0x12cbbc and `bl srand` @0x12cbc0 with
   zero intervening instructions, then builds the 11 descriptors (all 11
   `bl 0x147d3c` sites of the library are in this wrapper) and calls the
   interpreter. nSign (0xdb1cc → 0x95fc4 → pthread → VM 0xfb00 → 0x8d6f4 /
   0x956e0) contains **no rand and no interpreter call**.
2. **The interpreter draws EXACTLY 8 rand values per run** (instrumented,
   byte-exact executor): ONE 0x2e6 whiten activation = 4 pair-XOR units =
   **the 16-B wire header**, taken at stream positions 0..7 of the freshly
   seeded stream. Nothing draws before or after them.
3. **The 44-dword body and the region per-call words (W0, X, tile, d2, d4)
   contain ZERO rand material.** The body is the deterministic descriptor
   merge; the per-call words are descriptor INPUTS built upstream (fill path).
4. Therefore the sweeps of l48_sweep.md / fresh3.md were searching the wrong
   words: those words were never members of the stream. The only rand-derived
   bytes of any blob are the header — which inverts 13/13 (the header law).

## 1. D(claims_len) — task 1

**D = 8 draws, CONSTANT. Not a function of claims length, descriptor count,
or word count.**

* Enqueue topology (census re-verified): token 0x2e6 has exactly ONE
  enqueuer — 0x128fb8 (inside the 0x2d5 handler); 0x2d5 has exactly one —
  0x100cf4 (0x2c3 handler); 0x2c3 has exactly one — 0x12a9ac (shared tail
  0x12a984, token 0x143). So the whiten cycle is entered ONLY via 0x143.
* The loop-back tail 0x12a984 (`PUSH 1; enq 0x143`) is reached ONLY from
  0x129bb8 (`b.eq` after `OBJLEN(desc) -> w22; cmp w22, w23`): the
  descriptor-walk handler either copies the descriptor's frame words
  (0x129bbc gather loop) or routes back to the whiten cycle. In the real run
  this pc executes exactly TWICE (first visit falls through to the copy path,
  second visit — after the frame's words are consumed, w22==w23==1 — takes
  the branch), and the walk never returns: **one whiten trip per run.**
* Instrumented row 7 (signing A, claims 360 B, 9,871,985 steps, exit-clean):

  | pc | meaning | count |
  |---|---|---|
  | 0x12a1f8 | 0x2e6 handler entry | 1 |
  | 0x12a2ec | LOOPNEW(4) — activation loop head | 1 |
  | 0x12a2fc / 0x12a31c | bl rand | 4 / 4 |
  | 0x12a368 | eor w2,w0,w21 | 4 |
  | 0x12a984 / 0x12a9ac | whiten loop-back / enq 0x143 | 1 / 1 |

  First draw at step 13,455 of 9.87 M — the header units are the run's ONLY
  draws and land at output-sink F0 positions 0..3 (the blob's first 16 B).
* `python vm_sim.py dclaims` (synthetic claims, everything else = row 7):
  claims 4 B / 16 B / 360 B / 2048 B → status exit-clean, **nrand = 8**
  (steps 8.04 M / 8.05 M / 9.87 M / 17.87 M — only the merge tail scales).
  16 KiB claims still shows nrand=8 (draws finish at step ~13.4 k; the step
  cap hits in the merge walks, which make no draws).
* All 10 corpus rows (claims 360/387/388/502/529 B): nrand = 8, one
  activation, every run exit-clean (`vm_act_run.log`).

## 2. D_init — task 2

**D_init = 0.**

* No rand consumer exists outside the interpreter: the two `bl rand` sites
  (0x12a2fc/0x12a31c) are the only rand references in the library, and the
  only path to them is 0xdafe4 → 0x12cb74 → 0x12d39c. No init/config/string
  program draws.
* The wrapper's flattened body between srand (0x12cbc0) and the interpreter
  call (0x12d39c) contains no `bl rand` — the stream position at interpreter
  entry is exactly 0.
* Whole-file scan for 8-byte little-endian function pointers to 0x100094 /
  0x12cb74 / 0x12d39c: none (0xda4b0 appears only as its own dynsym entry) —
  no indirect entries either.
* The task's hypothesis (c) collapses into something simpler and proven:
  **srand re-fires before EVERY signing, at the signing's own second.** The
  header law already showed each blob's header = pair-units k=0..3 of
  Random3(signing second), uniquely, 13/13. Decisive new witness: region
  rows 2 and 4 are DIFFERENT signings (different claims, different
  d0/d2/d4) with the SAME second 1789240075 — and they carry the IDENTICAL
  16-B header `211c2cd4236fbed860e65b4b3f99bdea`. Same seed ⇒ same first 8
  draws ⇒ same header, independently of the rest of the blob. (Java `sign()`
  does not call onResume — the app/SDK fires `Signer.onResume()` before each
  signing; the native evidence forces it regardless of the trigger.)

## 3. Exact k-window test — task 3

With D_init = 0, D = 8 and per-signing reseed, the exact window for a
signing with second S is **k ∈ [0, 8) of Random3(S), seed S itself** — no
accumulation across the burst, no ±delta, no slack.

* **Header: 4/4 for every row** (units d[2j]^d[2j+1] of Random3(S), BE) — the
  header law, re-verified directly on rows 0 and 7.
* **Full-blob reproduction** (FinEx, real descriptors, seed = own second):
  rows 0, 1, 4, 5, 6, 7 → **48/48 byte-exact** (exit-clean; row 7 also
  matches the native capture 22,272 events 1:1 per fin_result.md).
  Rows 2/3 → header 4/4, body mismatch — their `d10` claims captures are the
  ones corpus_seed.md already flagged as inconsistent (created_at 21:03:20
  vs blob seconds 1789240075/76 = 21:07:55 local; the true d10s are not in
  the corpus). Rows 8/9 have no blob to compare.
* **Region words: precise zero.** All 13 pxable per-call words per row
  (W0, X, U0..U3, d2, d4[0..7]) tested against units k=0..3 AND raw draws
  0..7 of {lrand48, ANSI-LCG, TYPE_3} × seeds sec−3..sec+3 × 10 rows:
  **0 hits** (expected noise ≈ 0.006). They are not in the window because
  they are not in the stream at all.

## 4. Post-eor mix and the per-word recount — task 4

* **No post-eor mix.** 0x12a368 `eor w2,w0,w21` → 0x12a370 push →
  0x12a384/88 dup-over(1) → pops → 0x12a3d0 `bl 0x146ed8` EMIT. The block
  0x12a368..0x12a414 contains no mul/add/imm mix — the only arithmetic is
  `add w2,w0,#1` @0x12a3f4 (dst++) and the ITERNEXT counter @0x12a410
  (`cbnz` → 4 iterations). Empirically the header law holds at C=0 on 13/13
  real blobs, which settles it.
* **Draws are NOT f(word count).** rand_path.md's "3 activations = 24 draws
  (4 units → #0's tile, 8 units → #4)" is falsified: the tile/d4/W0/d2 words
  are pre-built descriptor inputs (the interpreter's gather/copy opcodes
  move them; it never rand-fills them). The interpreter's ONLY rand output
  is the one 4-unit quad = the header. The U[2]^U[0]==R‖R law (13/13) is a
  property of the FILL-path generator, not of pair-XOR units.

## 5. The stream-position failure — best explanation

1. **Wrong words:** the sweeps tested region per-call words (W0/X/tile/d2/d4)
   and body dwords. These are descriptor-merge/fill outputs; the fill gets
   its per-call entropy from the fine clock upstream of the builder
   (emu_findings.md §4; corpus_seed.md §6). They were never rand draws, so
   no seed/position could ever hit.
2. **Wrong family for the only rand words:** the stream that IS consumed is
   `srand(time(NULL)); rand()` — on bionic `rand`=`random`, `srand`=`srandom`
   (TYPE_3 additive feedback = header_gen.Random3), NOT lrand48. Every
   lrand48-modelled position test was testing a generator the binary never
   runs. (TYPE_3 was tested only in fresh3.md, and only against the wrong
   targets.)
3. **Wrong position model:** there is no cross-signing continuation to hunt.
   Each signing re-seeds at its own second and consumes exactly 8 draws at
   positions 0..7 (header). D_init = 0 kills hypothesis (a); D = 8 constant
   kills (b); per-signing reseed (rows 2/4 identical-header witness) kills
   (c).
4. The historical anchor (row 7 W0 = lrand48 pair k=107110) stays the
   ~1/200 noise event l48_sweep.md classified.

## 6. Consequences

* **Offline header forging: trivial and total.** header = Random3(second)
  units 0..3, BE — no descriptors needed, no unknowns.
* **Offline blob forging is now a well-posed problem:**
  `blob = FinEx(descs, seed=signing_second)` reproduces real blobs
  byte-exactly (6/6 self-consistent corpus rows + signing A's 22,272-event
  native match). The ONE remaining unknown is the descriptor fill for the
  per-call words (W0, X, tile, d2, d4) — a fill-path problem (fine-clock
  model), not a rand-stream problem.
* The logged-rand emulation formerly queued as "the deciding instrument" is
  answered statically + by the byte-exact reproductions: it would show 8
  draws per nOnResume, positions 0..7.

## 7. Reproduction

```
python adj9/rev/vm_sim.py full      # 10 rows: nrand=8, act=1.00, blob 48/48 (6 self-consistent rows)
python adj9/rev/vm_sim.py dclaims   # claims 4 B..2048 B: nrand=8 everywhere
python adj9/rev/vm_act_run.py       # same corpus run with mismatch diagnostics (log: vm_act_run.log)
python vm_sim.py                    # the original symbolic head trace (unchanged)
```

Files: `rev/vm_sim.py` (extended), `rev/vm_act_run.py`, `rev/vm_act_run.log`,
`rev/fin_vm2.py` + `rev/fin_descs.json` (the proven executor + signing A
descriptors), `rev/all_signings.json` + `rev/pair_h3.json` (corpus).
