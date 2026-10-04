# Wall A — slice 21: 29-op queue audit — exit inside case `0x128838` (2026-09-11)

`vm_final.py` now logs every PUSH/POP (pc, queue, value, depth). Golden-tuple
run, 29 ops total:

## Full trace (queues `0x0` = main, `0x3000` = queue2)

```
0x100234 PUSH(q1,25)        0x10024c PUSH(q1,0)
0x100260 POP→0              0x100278 POP→25            (pairwise handshake)
0x1002b0 PUSH(q1,0)         0x1002c4 POP→0
0x1002ec PUSH(q1,OUTLEN=0)  0x10030c PUSH(q2,17)
0x100360 PUSH(q1,0)         0x100374 POP→0
0x100398 PUSH(q1,LENQ=25?)  0x1003dc POP→25  0x1003f4 POP→0
0x10040c PUSH(q1,0)         0x100424 PUSH(q1,0)
0x100438 POP→0              0x100450 POP→0
0x100484 PUSH(q1,0)         0x10049c PUSH(q1,0)
0x1004b0 POP→0              0x1004d4 PUSH(q1,LENQ=0)
0x1004e8 POP→0              0x100500 PUSH(q1,w0−1=0xFFFFFFFF)
0x100514 POP→0xFFFFFFFF     0x10052c POP→0   (q1 drained)
0x100570 POP(q2)→17                              (dispatch: 17 < 0x2d → case 0x128838)
0x128850 PUSH(q1,1)         0x128864 POP→1
0x12887c POP→UNDERFLOW → writer error → 0x100318 exit-clean, 1253 steps
```

## What this proves

1. Exit moved one level deeper than slice 13/20 believed: not the dispatch
   POP (it succeeds, q2=17) but the case-helper's 3rd queue op. The case
   `<0x2d → 0x128838` is itself correct behavior for value 17.
2. Every LENQ returns 0 (workspace empty), OUTLEN returns 0 here (not
   `acc−TOP` — the call at `0x1002dc` feeds a stream whose acc == TOP in our
   model; flagged for re-audit), all downstream values const-propagated
   (25/17/0/−1). Queues end exactly balanced-to-zero going into the case —
   native must arrive with ≥2 queued (real LENQ/OUTLEN values), same
   conclusion as slice 20, one level sharper.
3. Pre-dispatch range (0x100228–0x100700) contains **zero** unhandled insns
   (`udiv/msub/cset/ldrh` all live elsewhere — cleared by mnemonic census
   over all 43,629 lifted insns). Skipped-instruction corruption is ruled
   out for this span.
4. MAIN-init sweep (12 variants: acc/offs/data presets) + #0/#8
   dword sweeps (320 runs) + #2/#6/#7 sweep (39 runs): ALL null. Three
   independent null classes ⇒ pre-dispatch outcome is fully determined by
   (consts, MAIN handshake, LENQ/OUTLEN results); field values cannot reach
   it (write-only pre-dispatch — slice 20 mechanism confirmed from the
   trace: no field-sink LENQ exists before `0x100554`).

## Next (falsifiable, ordered)

1. Re-audit `0x1002dc` call target + OUTLEN input stream (why 0, not
   `acc−TOP`?) — one disasm check.
2. Real #0 payload (R4): first value that makes any LENQ return nonzero
   flips the whole downstream (falsifiable per-run via this same qlog).
3. `0xba4a8`/`0x9c478` + `0xbb548` visit order with R4 args (slice 17–18).

## 5. Addendum — OUTLEN re-audit + value-flow proof (same session)

- `0x1002dc` IS OUTLEN on stream0 (field0 sink): `x0=[CTX+w0·8+0x20]`,
  w0=0 → `[CTX+0x20]`. OUTLEN=0 was CORRECT (zero-filled #0 ⇒ TOP=0 ⇒
  `acc−TOP=0`). Not a bug.
- r4_sens nulls were comparator-blind: it compared (steps, ndisp, status)
  only. Full-state compare shows `#0[35]=ts_sec` changes emit #63 —
  **a MERGE emit to MAIN `(0,0)→(0,941841558)`** (plus the trivial field
  emit #35). So `#0-last → OUTLEN(−TOP) → queue → merge EMIT value` flows
  while control stays fixed: path const-driven, values data-driven.
- Program: each recovered real input must flip specific merge emits;
  all-real ⇒ merge values converge to the real blob (modulo `0xbb548`
  mapping, still owed). Falsifiable per input via emit-trace diff.
