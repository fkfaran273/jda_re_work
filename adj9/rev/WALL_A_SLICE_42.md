# Wall A - slice 42: clean-return scheduler model (2026-09-11)

## Writer-cell audit (end of run, `mem[W]`)

| run | steps | writer | meaning |
|---|---|---|---|
| base split, no force | 1253 | 3 | ERROR (POP underflow, two-queue starvation) |
| shared, no force | 1375 | None (never written) | CLEAN via `0x10055c isEmpty → 0x100318` epilogue → ret |
| shared, force=742 | 1974+ | None | CLEAN (header loop ran inside) |

Last pcs confirm: `...0x100554 0x100558 0x10055c 0x100560` = isEmpty-true
exit in both clean runs. The "starvation" narrative is WRONG for
shared-queue runs: the VM is a PHASE SCHEDULER — dispatch while queue
nonempty, return when drained. Our placeholder runs finish after 1-2
phases (minimal cases); native runs many more (list-walk cases refill the
queue: 59 MKITER sites, all downstream of value-routed cases).

## Completion criterion (falsifiable)

VM-ret with writer clean AND streams holding 48 dwords (header 4 +
body 44). Current best (forced header): header 4/4 in MAIN[0..3] but body
placeholder. The 59 list-walk cases (0x101434+ region, trip counts from
LENQ/stream values) are the refill path our runs never take (dispatch
values route short cases). Real #0 content → real LENQ hits → deeper cases
-> refills -> more passes -> 48 dwords -> ret -> assembly reads 48.

## What changed vs slices 20-22

"Starves/drains" -> "completes early": same traces, correct reading. The
emulator doesn't get stuck; it runs out of work. The balance paradox
(slice 22) dissolves: native doesn't need extra depth at the SAME point,
it takes MORE passes through refill cases. Monitor from here: pass count,
isEmpty-exit pc, stream dword totals (target 48), writer cell.
