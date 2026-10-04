# Wall A - slice 57: feeder `0xda6b8` = env-input dispatcher (2026-09-11)

Fn `0xda6b8-0xda978` (176 insns): mini-dispatcher, hub `0xda790`, ~15
tiny callees: `0xd868, 0x1c920, 0x1bcc4, 0xe374, 0xee40, 0xddf0, 0xde24,
0xe3a8, 0xee74, 0xee8c, 0xde3c, 0xe740, 0xf9b4, 0x15384, 0x15590`
(+ `0x8c98`, `0x148a10` infra). Struct reads (`x19+0x118`) inside.

## `0xe740` onboard: the env-marker machine runs pre-stamp

`0xe740` = slice-6's 26-marker decrypt + 14-stage env pipeline. It runs
here (pre-stamp feeders), NOT (only) in the disproven ctx/fold signing
path. Its output + the sibling workers' outputs aggregate into the
orchestrator struct (x19-slots incl. #0's 144 B window at +0x50).

## Reframe: #0 = env telemetry, not map claims

This explains the claim-battery wipeout (~100 recipes flat): #0 was never
claim-derived. It is environment verdicts + timestamps + counters packed
by these workers (each worker = one input class: markers, /proc,
properties, time, aux...). The mapget fetch lists feed #8/#10/other
descriptors (or 0xba4a8's separate record), not #0.

## Next (bounded, ordered)

Lift the ~15 workers smallest-first (each likely straight-line: read one
env source -> write struct slot): map worker -> slot (+0x50 window
segments, +0xE0 gap?, #2?, #7?). Start with `0xe740`'s output slot (known
machine, known markers) + the `x19+0x118` readers. Then #0 segments become
known-knowns (env verdict BITS are enumerable offline: emulator/test
markers are constants!).
