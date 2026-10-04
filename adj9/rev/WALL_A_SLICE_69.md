# Wall A - slice 69: assembly harness + movk fix (2026-09-11)

## Harness (`run_asm.py`, kept? no - one-off pattern; vm_final extended)

- INS/IDX extended with `0xBB548-0xBBBF8` (proper ELF offsets).
- `_calls` log for every `bl` (target + x0-x4) and `blr` (args, returns 0).
- Entry: pc=0xBB548 + concrete arg classes (level cell=31, fake JNI/map/
  strings/out-cell).

## movk fix (CRITICAL, silent everywhere until now)

`vm_final.py` movk regex expected a space (`", #"`) but the string was
spaceless (`",#"`) - EVERY movk in EVERY prior run silently did nothing.
Fixed to spaceless pattern. Impact audit: field/header/merge trajectories
use mov/movz/add/ldr (unaffected - all verified outcomes stand); maze
consts in traveled code were either unused or re-derived (dispatch values
come from queue, not consts); only never-traveled maze branches read
wrong consts. All prior conclusions hold; future maze-adjacent work uses
correct consts.

## Assembly walk status

Hub cycles without resolving (entry x9 != any token with placeholder
args; maxpc 0xbb898 = hub end, 0 calls). Needs entry token (x9 from the
0xdbb64 flow = staged regs, same `_forcereg` pattern as VM router walks).
Next: forcereg-walk the hub edge by edge (x9 := token per edge), log calls
(malloc sizes!, JNI idx, builder args), read visit order + len + feeds.
