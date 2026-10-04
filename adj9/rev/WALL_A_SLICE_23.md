# Wall A — slice 23: descriptor build sites — lengths proven, sources localized (2026-09-11)

## 1. Complete build table (`bl 0x147d3c` ×11 in stamp `0x12cb74`)

`mkdesc(out=x0?, len=w1 BYTES, data=x2)`. w1/len now exact:

| # | site | len (w1) | data (x2) | identity |
|---|---|---|---|---|
| 0 | `0x12cbd8` | `0x90` = 144 | `x19+0x50` (struct+80) | 144-B core record (36 dw) |
| 1 | `0x12d21c` | 0 (`wzr`) | `xzr` (NULL) | empty |
| 2 | `0x12d2c0` | 4 | `[sp+0x58]` (= spilled x8) | 4 B |
| 3 | `0x12d4a8` | `[sp+0x74]` runtime | `[x29−0x20]` | runtime `{len,ptr}` |
| 4 | `0x12d4f8` | `0x20` = 32 | `[sp+0x50]` (= spilled x20/x19) | H, 32 B (8 dw) |
| 5 | `0x12d548` | 4 | (window cut — same pattern, sp slot) | 4 B |
| 6 | `0x12d818` | 4 | (same pattern) | 4 B |
| 7 | `0x12d95c` | 4 | (same pattern) | 4 B |
| 8 | `0x12daa8` | `0x10` = 16 | `[sp+0x48]` (= spilled x9/x10) | 16 B (4 dw) |
| 9 | `0x12db4c` | `0x14` = 20 | `[sp+0x40]` (= spilled x22→x9) | SHA-1 digest (5 dw) |
| 10 | `0x12dba0` | `[x8+0x128]` runtime, `x8=[sp+0x88]` | `[x8+0x130]` | caller struct `{len,ptr}` |

Field-0 site context: `bl time; bl srand` immediately precede → the stamp
seeds `srand(time)` THEN builds desc 0 from `x19+0x50`. (Header draws come
later inside the VM.)

## 2. Stack-fill map (stamp prologue `0x12cb74+`)

`[sp+0x40]=x22→x9`, `[sp+0x48]=x9,x10`, `[sp+0x50]=x20,x19`,
`[sp+0x58]=x8` — the mkdesc x2 slots are spilled callee-saved regs. So
#2/#4/#8/#9 data = whatever `x8/x9/x10/x19/x20/x22` POINT TO (pointer-sized
slots; 32/20/16-B reads through them; #2's 4 B may be value-direct).
`x19` is also the core-record struct (`+0x50` = 144 B at `+0x50..+0xE0`).

## 3. Precise next (the chase, all static)

Recover the six regs + two runtime slots at stamp entry:
- (a) walk back from `0xdafe4` (`x0=x26,x1=x27,x2=sp+0xb0` + `x19–x22,x28`
  set in the `0xda97c`-orchestrator/JNI-thunk chain `0xda4b4/0xda6b8`,
  `0x14868,0x1bbb4,0xe4a7c,0xf9dc`) — which thunk yields H ptr / digest ptr
  / record struct / small ints;
- (b) `[sp+0x74]` (#3 len) + `[x29−0x20]` (#3 data) provenance;
- (c) `[sp+0x88]` struct (caller `+0x128/+0x130` = #10) provenance;
- (d) #5/#6/#7 x2 windows (same sp pattern — confirm, 5 min).
Then: resimulation with REAL #2/#8 (+#9 ✓,#4 ✓,#5 level) — 6+ known of 11.
