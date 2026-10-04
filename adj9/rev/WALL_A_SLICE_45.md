# Wall A - slice 45: CAP machine mapped, append-mode, header at MAIN[4..8) (2026-09-11)

## 1. CAP state machine (all consts resolved, transitions enumerated)

Entry: `x8 = (count > k)u32 ? 0x549f... : 0x62d5...`; hub compares vs 7
consts in fixed order. Key transitions: `x8==x22const` -> RETURN
(`0x1479f8`); count<=k path -> `[writer]=4` (-> caller exits!); PUSH exit
(`0x147968`: pushes live `R[x21]`, x8 := x22const -> return); `0x1479c8`
and `0x1479ac` loops reassign x8 and continue. So CAP either pads with the
LIVE x21 word or errors the writer - no per-queue counter anywhere.

## 2. Model updates in vm_final.py (all falsifiable, all kept)

- CAP pad value: live `R[x21]` (was per-queue seq). Verified flowing
  (pad == iteration's draw value in traces).
- EMIT append-on-wild: fresh stream (offs==[0], acc==0) + index OOB ->
  APPEND value (was: silent drop). Rationale: native must place XORs
  somewhere; grow-to-7GB and error both contradict working signatures.

## 3. Header lands at MAIN[4..8), not [0..4)

Handshake appends (0x19, 0x2a, 0, 0) occupy 0-3 (const op-counts, hence
structural, not coincidence); 4 header dwords append after:
`4999f1bf/61d828a1/68605472/469414b0` at 4,5,6,7 - byte-exact IN ORDER.
Assembly must read the header at a stream+offset (offset 4? or x26-advance
makes it 0 elsewhere - open). Baseline 1253 unchanged (no regression).

## 4. Standing questions (narrowed)

(a) EMIT append-vs-index rule needs the maze-exit proof (which const-path
selects append? currently structural guess); (b) x26 advance rule (one
`[x26,#8]!` seen - more?); (c) assembly read offsets; (d) R4 content for
natural runs. No unknown control on the header path anymore.
