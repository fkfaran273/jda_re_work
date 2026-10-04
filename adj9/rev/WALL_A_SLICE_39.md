# Wall A - slice 39: three emulator fixes - full header byte-exact (2026-09-11)

## Fix 1 (the big one): POP never touches w21 + true x/w aliasing

Live-reg trace at the header XOR showed `w21 <- 0` at POP#2 while native
holds B. Root causes, both in `vm_final.py`, both fixed:
- POP saved prev-w0 into w21 (a misread "contract" from slice 9). Native
  POP returns w0 ONLY; w21 comes from explicit `mov` sites (e.g. 0x12a34c).
  The save corrupted every eor chain via the next bug.
- x/w alias handling DELETED the counterpart (`R.pop`). True ARM64:
  xN-write sets wN=low32, wN-write zero-extends into xN. `mov x0,x19`
  (x19 = 0x53........) then made `R[w0]` read 0-by-default instead of 0
  (same number here, wrong mechanism - and wrong whenever low32 != 0).
Effect: header XOR was A^0=A; now A^B. Verified in isolation AND in-run.

## Fix 2: ITERNEXT matches the single live iterator

`0x12a408` double-derefs (`ldr x8,[sp]; ldr x0,[x8]`) - the VA-registry
match failed, killing the header loop after 1 iteration (nrand 2). Now:
VA match, else the single live iterator. nrand 2 -> 8.

## Result: complete 16-B header, byte-exact, on the real path

Force-walk (dispatch=742, INJECTED): 4 loop iterations, 8 draws, 4 EMITs
to MAIN (`[CTX+8]`) indices 0-3: `4999f1bf 61d828a1 68605472 469414b0` =
the golden blob's header EXACTLY (seed 1789123783). Baseline (no force)
unchanged: 1253 (no regression). CAP-pad model active (capseq) and
consistent (len=pad small, arg=X header dword).

## Left (unchanged shape, smaller magnitude)

Loop-back seeder after header (maxpc 0x12a8cc), workhorse still dark
(needs live LENQ/OUTLEN values = R4), assembly, parse. The emulator's
remaining bugs of this class (stale-pattern "contracts") should be
re-audited opportunistically; the qlog + reg-trace pattern found all three
so far.
