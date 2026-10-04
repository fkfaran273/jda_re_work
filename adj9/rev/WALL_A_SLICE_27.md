# Wall A — slice 27: three proven constants — 7.5/11 known (2026-09-11)

All from store-to-slot scans + sub-x2 windows in stamp `0x12cb74` (no maze
lifting — straight-line prologue + per-site blocks).

## Proven this session

| desc | proof |
|---|---|
| #3 EMPTY (`{0, NULL}`) | len slot `[x29−0x28]`: only writer is prologue `stp xzr` (`0x12cbb4`, pair-covers −0x28); data `[x29−0x20]`: only writer prologue `stp xzr` (`0x12cbb0`), readers = mkdesc#3 + epilogue. Zero + NULL ⇒ inner loop skipped, tail by tag&3... (tag of `(0<<2)\|t` — the node word from `mkdesc#3` site; crash-free in practice = the path the device takes every signing) |
| #5 = `00000000` | data ptr `x2 = x29−0x34` (`0x12d540`); slot's only writer prologue `stur wzr` (`0x12cbb8`) |
| #6 = `00000000` | data ptr `x2 = x29−0x2c` (`0x12d804`); slot = `rev([x29−0x28])` = `rev(0)` = 0 (`0x12d810/0x12d814`) |
| #7 = u32 `[x19+0x128]` | data ptr `x2 = x29−0x30` (`0x12d948`); slot = `[x19+0x128]` (`0x12d940/0x12d950/0x12d958`) — master-struct u32, same word as #10's length |
| #10 | `{len=[x19+0x128], ptr=[x19+0x130]}` (slice 26 confirmed; `0x12db90` reloads struct base from `[sp+0x88]`) |

## Table (11 → effective 9.5)

KNOWN: #1 ∅, #3 ∅, #4 H (per-call), #5 `00…`, #6 `00…`, #9 cert-SHA1.
SOURCED (address known, value = struct/runtime): #2 (`x19+0x20` 4 B), #7
(`[x19+0x128]` u32), #8 (`x19+0x100` 16 B — STRONG: prefix of #9's 20 B at
same base), #10 (`x19+0x128/0x130`).
OPEN: #0 content (144 B @ `x19+0x50`), #2/#7 values, #10 values, ns stamps
(likely inside #0), `0xbb548` order. Resimulation inputs needed: #0 +
struct u32s + #10 + ns — everything else is now constant.
