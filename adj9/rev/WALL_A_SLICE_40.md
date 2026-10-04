# Wall A - slice 40: deepest forced walk - seeder circulation (2026-09-11)

Staged route (500/700/800/700/742) + persistent supply at 8 header POPs:
29k steps, 434 emits, header loop 4 iters, 8 real draws, X computed.

## Findings

1. 180 EMITs to MAIN with n = 1010, 1119, 1228, ... (+109/pass), v = 0:
   seeder residue circulating as EMIT INDEX with zero values. EMIT-index
   role confirmed (n = position); content pipeline dry (v = 0 = leftover).
2. X (header dword, correctly computed A^B) never reaches any EMIT v:
   len/arg POPs take seeder/zero residue ahead of it in LIFO order. The
   placement problem is queue-CONTENT order, not control.
3. CAP-pad verified working (len small: n = 0..7 region EMITs present);
   pads + seeder values interleave deterministically and reproducibly.

## Net (CORRECTED same session - read this, not the draft above)

Over-supply buries X (zeros ahead of it in LIFO). Supply ONLY the counter
site (0x12a3e4): 40,630 steps, nrand 8, **X-hits 4 - MAIN[0..3] =
4999f1bf/61d828a1/68605472/469414b0 COMPLETE BYTE-EXACT HEADER, in order**.
CAP-pad (len) + X-as-arg + counter-chain confirmed as the working trio.
Forcing ceiling is NOT reached: with correct supply placement the header
completes fully. Remaining: workhorse (same supply pattern per its POPs),
assembly, parse. R4 real content still needed for NATURAL (unforced) runs.
