# Wall A — slice 31: shared queue — +122 steps, loop found, warming shown (2026-09-11)

`vm_final.py`: `_shared_q` opt-in (`Ex(..., shared_q=True)`; default stays
split to preserve all documented baselines).

## 1. The experiment

Split queues (slices 9–22): exit 1253, dispatch POP `q2=17` → case
`0x128838` (guard `w0==0x11` passes) → 3rd op starves. Shared single queue:
**exit 1375, 44 qops** (vs 29). The earlier shared attempt never took
(init-order clobber — slice 22); this one does.

## 2. What the shared run does (full qlog)

- Dispatch POP takes **0** (LIFO top of the mergedConst stream, not the
  buried 17) → `0x128838` guard (`w0==0x11`) FAILS → `0x12a8b4`.
- `0x12a8b4` block: `PUSH(queue, 109)` (**constant `0x6d`**, not computed)
  → `cbz → 0x100354` — a BACK EDGE into the merge prologue. The machine
  LOOPS passes over the merge section, reseeding a constant per pass.
- Pass 2 runs `0x100360–0x10052c` with WARMED workspace: values 109/108
  circulate (`sub w2,w0,#1` at `0x1004f8`), LENQ/OUTLEN read non-empty
  offs, merge emits accumulate (67 vs 65).
- Pass 2 ends depth 0 → `isEmpty`-true → exit-clean 1375. Each pass
  net-zeroes the queue; continuation needs pass-N leftovers, i.e. real
  LENQ/OUTLEN hits (real payloads).

## 3. The workhorse loop (`0x12a880–0x12aac`)

`ldr x24,[x26]; w25=w21+w23; LENQ; EMIT; ...; w23++; cbz→loop` — per-dword
LENQ→EMIT with a running counter. This is the merge's per-dword engine
(the 44 body dwords take shape here across passes). Trip count is
data-driven (writer-clean loop).

## 4. Model status

Fixed-point warming structure CONFIRMED: passes reseed (109 const),
workspace accumulates, values evolve (109→108→…), dispatch re-routes per
pass on queue values. Termination = dispatch eventually hitting the header
case once the workspace is real (native proof: 192 B out). Shared-queue is
now the leading hypothesis (coherent loop vs split's instant starve);
needs the CTX-header proof (slice 22: `[CTX]==[CTX+0x18]` from the creator
chain) to graduate from hypothesis. Field stage untouched (62/62 both
modes); verifier 114/114 untouched.
