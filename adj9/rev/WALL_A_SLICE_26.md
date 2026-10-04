# Wall A — slice 26: the master struct — all fixed descriptors localized (2026-09-11)

Stamp prologue `0x12cb74–0x12cc1c` fully decoded (no maze in this span).

## 1. `x19` = stamp's x2 arg = master struct base

`mov x19,x2` (`0x12cba8`); x2 at the `0xdafe4` call = orchestrator `sp+0xb0`.

## 2. Complete offset map (all from the prologue + slice-23 sites)

| struct off | size | descriptor | how |
|---|---|---|---|
| `+0x20` | 4 | #2 | `[sp+0x58] = x19+0x20` (`0x12cbd4`) → mkdesc#2 (`0x12d2c0`) |
| `+0x30` | 32 | #4 H | `[sp+0x50] = x19+0x30` (`0x12cbf4` overwrites spill) → mkdesc#4 (`0x12d4f8`, len `0x20`) |
| `+0x50` | 144 | #0 core | `x2 = x19+0x50`, len `0x90` → mkdesc#0 (`0x12cbd8`), built right after `time/srand` |
| `+0xE0` | 32 (gap) | ? | window `+0xE0..+0x100` untouched here — #5/#6/#7 (4 B ×3 = 12 B) + 20 B pad? or other |
| `+0x100` | 16 | #8 | `[sp+0x48] = x19+0x100` (`0x12cbf4`) → mkdesc#8 (`0x12daa8`, len `0x10`) |
| `+0x100` | 20 | #9 | `[sp+0x40] = x19+0x100` (`0x12cc0c`) → mkdesc#9 (`0x12db4c`, len `0x14`) — same base as #8, longer read |
| +? | ? | #3/#10 | runtime (stamp `[sp+0x74]`/`[x29−0x20]`, caller+`0x128/0x130`) — outside this struct |
| +? | ? | #5/#6/#7 lens | mkdesc len 4 (immediates); x2 = sp slots (slice-23 pattern) — exact slots owed (5-min read of `0x12d548/0x12d818/0x12d95c` windows) |

Also settled: `0xba4a8`'s obj (`stamp[sp+0x40]`) = `x19+0x100` (digest region
used as the CallV target — likely a direct buffer).

## 3. Remaining fills (all in `0xdaf60–0xdafe4`, named calls, x2/x3 = struct)

Which call writes H (`+0x30`), the 144 B (`+0x50`), digests (`+0x100`),
small ints: `0xda4b4` (x0=x26,x1=x27,x2=sp+0xb0), `0xda6b8`
(x3=sp+0xb0!), `0x14868`, `0x1bbb4`, `0xE4a7c`, `0xF9dc` (x0=sp+0xb0).
Read order: argument roles (DONE here) → per-call writes (their lifts or
JCA-anchor matching: HMAC-out→`+0x30`, SHA1-out→`+0x100`, map-packing→`+0x50`).
Cross-check available WITHOUT lifting: the fresh golden tuple (H, map,
cert-SHA1 known!) constrains each slot's content class.
