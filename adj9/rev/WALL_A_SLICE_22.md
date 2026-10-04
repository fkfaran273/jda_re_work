# Wall A — slice 22: the balance paradox + full pre-dispatch audit (2026-09-11)

## 1. The paradox (stated exactly)

Pre-dispatch queue balance from the 29-op trace (`_qlog`, in `vm_final.py`):
12 main-queue PUSHes / 12 POPs → depth 0 at dispatch; queue2: 1 PUSH (17) /
1 POP (dispatch) → 17 → case `0x128838` (guard `w0==0x11` ✓) → its 3rd op
(`0x12887c` POP) starves. Op COUNTS are const-fixed (all backward branches
in range = error exits to `0x100318`; verified by branch census). Values
can't change depths. So the model starves **deterministically, independent
of all field inputs** — yet native produces blobs. One of the model's
structural guesses must differ from native.

## 2. Audit trail (everything verified, nothing assumed)

- All 29 sites' `bl` targets verified against disasm (PUSH/POP + 4 aliases —
  table in slice; `0x1002ec` = PUSH-of-OUTLEN confirmed, `0x1002dc` = OUTLEN).
- PUSH body (`0x147630`): queue=x1 `{count=[+0], head=[+8]}`, value=w2,
  writer=x0, calloc node — matches model.
- POP body (`0x147734`): empty → `[x0]=3` (x0==writer at every site incl.
  `0x12887c` — exit faithful), else count−−/unlink/`free`/return — matches.
- 43,629-insn mnemonic census: pre-dispatch span has zero unhandled ops.
- OUTLEN=0 re-audited CORRECT (zero #0 ⇒ TOP=0).
- Device binary identical (`dbe36c64…`, slice 22 device check) — no version skew.

## 3. Suspects, tested and ranked

- (a) Shared single queue (`[CTX]==[CTX+0x18]`): patch did NOT take — the
  `range(1,24)` stream pre-creation in `Ex.__init__` overwrites
  `mem[CTX+0x8..0xB8]` AFTER the queue slots are set (init-order fragility,
  reverted; behavior unchanged at 1253). Inconclusive, flagged: the CTX
  header layout (`[+0x0/+0x8/+0x10/+0x18]` roles) is still the top suspect —
  only field sinks (`[+0x20+i·8]`) are proven; the four header slots are
  inferred. Needs the creator chain (`0xdafe4`'s x1 ← orchestrator).
- (b) MAIN-init presets (12 variants): null.
- (c) Spurious error exit: disproven (`mov x0,x19` precedes every POP site).
- (d) Missed loop changing counts: disproven (branch census — only error
  exits go backward).

## 4. Precise next (no more guessing)

Trace `[CTX+0x0..0x18]` provenance upstream: stamp caller `0xdafe4`
(x0=x26, x1=x27 ← ?), through orchestrator `0xda97c`, to the fields-array
constructor — read off the four header slots' true roles/contents. Then
re-run: shared-queue (or corrected-split) + case audits with concrete
queues. The qlog makes every hypothesis falsifiable in one run.
