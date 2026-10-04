# Wall A — slice 14: LENQ maze PROVEN from constants (2026-09-11)

## The proof (all values are fixed 64-bit consts → the route is computable)

`0x147304` entry: `x15 = 0x32821f94a0780754`, and `x12` is built from the
*identical* four movk's (`0x754/a078/1f94/3282`) ⇒ **`x15 == x12` always at
`0x147374`**. The other three are distinct (`x9=0x7e88…`, `x11=0x0b13…`,
`x14=0x22db…`). Branch order:

```
0x147374 cmp x15,x9  / 0x147378 b.eq zero-path   (w8=0, x15=x14, loop)
0x14737c cmp x15,x14 / 0x147380 b.eq RET          (w0=w8)
0x147384 cmp x15,x12 / 0x147388 b.eq route        (x15=x13=csel(lo?x11:x9), loop)
0x14738c cmp x15,x11 / 0x147390 b.ne loop         (dead: x15 is always one of the four)
0x147394 reload-path (x15==x11 only): w8=[offs+w10*4], x15=x14-const, loop → RET
```

- Entry always takes `route` (x15==x12 proven above).
- `x13 = lo ? x11 : x9`, `lo = (w10 < w12)` u32, `w10 = TOP+n`
  (`TOP=data[count−1]`, `w12=[stream+0x0]` limit).
- `x15=x11` → reload offs[TOP+n] → x15=x14 → RET(w8).
- `x15=x9` → w8=0 → x15=x14 → RET(0).
- No other state is reachable (every assigned x15 is one of the four
  compared consts; the `b.ne` self-loop is dead).

## Exact formula (no flags, no maybes)

```
LENQ(stream x0, n w1) = offs[TOP_value + n]  if (TOP_value + n < limit)u32
                        0                    otherwise
TOP = data[count-1], offs/limit/count/data = [+0x8]/[+0x0]/[+0x14]/[+0x18]
```

`vm_final.py` already implements this shape (limit currently
`0x7FFFFFFF` ⇒ lo ~always true; the `data[n]` fallback branch is unproven —
native has none, returns 0; kept as approximation, flagged in code).
OUTLEN exact from slice 10 stands (7 insns, no maze).

## `0xbb548` (final assembly): entry + shape, full lift owed

Frame `0x120`, saves `(x0,x1,x2,x3,x4)` (`stp x0,x1,[x29-0x38]`, `stur x4,…`),
null/zero checks (`cmp x3,#0; ccmp x2,#0`), then the same opaque-maze
construction (junk 64-bit ladder `0xac07/d4fe/6a90/6685…`, `csel`). Same
proof technique applies (const-flow to the single store/concat); lift owed
with the slice-2 unflattener, not by hand.

## What this unlocks (and what it doesn't)

Unlocks: the merge's read primitive is now exact — resimulation no longer
approximates LENQ. Doesn't: EMIT store/grow exactness (maze lift owed),
`0xbb548` order, and the 7 unknown input payloads (slice 11). The maze
family is now 2-for-2 killable by const-flow (SM4-opaque earlier, LENQ now).
