# Wall A - slice 71: redispatch machine + chain (2026-09-11)

## Not single edges - a chained machine

- Blocks end in REDISPATCH tails (`0xbb9fc`: `ldur x8,[x29,#-0x40];
  cmp; csel x9,x27,x26,eq; b hub`). x21/x23 -> redispatch as x26.
- x26 block (0xbba00) spins on local `[x29,#-0x18]==0` (prologue-zeroed).
- Setters found by static scan: `0xbbd04 stur x1,[x29,#-0x18]` (in 2nd
  fn region), `0xbbb44 stur x8,[x29,#-0x40]` (redispatch selector).
- Chain is INTERPROCEDURAL (0xbb548-hub ⇄ 0xbbbf8-hub); `cmp x2,#0;
  csel` at 0xbbc9c selects 2nd-hub maze by MAP arg.
- JNI blr signature: (0x60, idx, map?, strings) - x3 = strings VA leaks
  through; x1 = index (-40 seen).

## Next (needs true entry)

Replay needs REAL entry regs (x9 token + args from 0xdbb64 flow).
Cheapest source: frida hook at 0xbb548 capturing x0-x4/x9 (device work,
next turn), then emulator replay -> deterministic full chain -> visit
order + malloc/JNI sequence + feeds. Alternative: order blocks manually
via setter dependencies (0xbbd04 before 0xbba00 before ...).
