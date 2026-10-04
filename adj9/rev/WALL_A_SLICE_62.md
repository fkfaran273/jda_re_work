# Wall A - slice 62: gateway select anatomy + #8 test null (2026-09-11)

## Select block `0x128e70-0x128eac` (exact)

```
POP -> w21 (= first pop); POP -> w0 (= second pop)
x28 = CTX + w0*8; x0 = [x28+0x20]! (stream select, x28 += 0x20)
OUTLEN(x0) -> w22 (= trip count!); w23 = 0
loop 0x128ea8: w22==w23 ? exit 0x12a9b0 (PUSH 557, back to merge)
              : LENQ/EMIT per-dword with counter, w23++, loop
```

So OUTLEN doubles as the copy-loop trip count (not just a gateway
threshold): the selected stream gets copied dword-by-dword into x24,
w22 iterations. The 725/742 gateway compares a LATER w0 (post-loop),
not this OUTLEN directly.

## #8-prefix test: null

Staged route + select idx 8 + #8 zeros-vs-prefix: identical trajectories
(1539 steps, gw 1 via staged gates only, hdr 0). #8's content changes
nothing observable here (OUTLEN feeds trip count, whose effect with
placeholder offs is nil either way).

## Tooling lesson (mine, twice in one session)

`elf[0xA:0xB]` with B < A (0x128E70:0x128A0) silently yields [] (and
capstone yields 0 insns for it). Twoмета "empty" mysteries were my own
backwards ranges. Always assert end > start.
