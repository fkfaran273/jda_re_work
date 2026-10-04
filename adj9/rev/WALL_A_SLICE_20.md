# Wall A — slice 20: R4 resimulation — baseline, sweep, starvation (2026-09-11)

`r4_harness.py` (kept): golden_fresh tuple → `vm_final.Ex` with real H +
cert-SHA1 + level 31, unknowns configurable; reports steps/queues/dispatch.

## 1. Baseline (4 knowns + zeros): exit-clean 1253, `nrand=0`

Identical exit to marker runs. Dispatch head reached (`0x100554–0x100580`,
13 PCs), then the dispatch POP (`0x100570`) underflows → writer error →
`0x100318`. Real H/SHA1/level do not advance the merge: the drain is a
workspace-content problem, not a plumbing problem.

## 2. Sweep: 39 runs, ZERO deltas (the null result that maps the machine)

#2/#6/#7 × {ts_sec, api 31, mapsize 50, 11, 36, 62, 48, 1, 0, 0xC0, 176,
32, 20}: no run differs from baseline in steps, dispatch PCs, or status.
Constraint learned: **single-dword fields have no pre-dispatch control
influence** — they flow only through workspace reads (LENQ `offs[TOP+n]`,
OUTLEN `acc−TOP`). Values matter only once the workspace is alive, i.e.
after real multi-dword payloads (#0/#3/#8/#10) + ns stamps land.

## 3. Starvation mechanism (MAIN stream at exit, real knowns)

`MAIN([CTX+8])`: `data=[0x19]` (single INIT append, n=0), `offs` 26 long
(scattered merge writes, mostly OOB-dropped), `acc=0` (no in-range merge
EMIT ever retires). So every pre-dispatch LENQ reads ~0, OUTLEN returns
`0−TOP` (bogus huge, pushed as garbage lengths), queues drain, dispatch
POP starves. Native with real payloads fills the workspace first (real
TOPs → in-range offs hits → real queue values → dispatch routes). The
emulator reproduces starvation faithfully given placeholders — validated,
not broken.

## 4. R4 table update

SOLVED INPUTS: #1 ∅, #4 H (per-call), #5 level (31/30), #9 cert-SHA1.
CONSTRAINED: #2/#6/#7 (workspace-only, no control) — candidates enumerated,
untestable until workspace alive.
OPEN: #0 (36 dw core record — the gate), #3/#10 (runtime ptrs + lens), #8
(4 dw), R3 ns stamps, `0xbb548` visit order (needs args — same wall).
NEXT: real #0 bytes (sync device logging of descriptor contents is native —
unreachable from Xposed; realistic source = layout inference from the
golden 50-map + canonical + env vocabulary, then resim-verify) or accept
the offline limit here.
