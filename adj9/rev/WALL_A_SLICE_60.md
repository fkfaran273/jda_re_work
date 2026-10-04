# Wall A - slice 60: mid-tier aggregators nest dispatchers (2026-09-11)

## `0x1bcc4` (0x550 B): JNI + serializer + malloc, hub `0x1bdf0`

~20 targets; calls `0xbf14c`, **`0x9c478`** (the serializer helper!),
`0x9e0c0`, JNI-ish `blr`, malloc `0x148a10`; ret `0x1c20c`. A mid-level
worker that builds something (buffer via malloc), serializes via 0x9c478,
and returns. Candidate role: builds one #0 segment or the runtime string
(#10?) from fetched claims.

## `0xde3c` (0x538 B): fold + verdict R/W + worker fan-out, hub `0xdfac`

`fold_word` (`0xe204`), verdict `[x10+0xF0]` read/modify/write
(`0xe228/0xe27c`, `0xe328/0xe330`), check-worker `0xe374`, `0x228e0`,
`0xdbb0`, `0x1d444`. An aggregator one level above the bit-setters:
runs sub-checks, folds their verdicts into the word. Note a SECOND
verdict object (`x10`, not x19!) - verdicts exist at multiple levels;
`x10+0xF0` vs `x19+0xF0` relation open.

## Standing pattern (4 levels now)

nSign hub -> orchestrator -> feeders (`0xda6b8` hub) -> mid aggregators
(`0xde3c`-class hubs) -> bit workers. Each level smaller and more
mechanical; each routes on runtime state. Value recovery needs fire
conditions per level (env reads) + live data slots. Next: `0x1c920`
(0xb24, biggest worker) or `0x9c478`-call-site audit (serializer inputs
across its 9 callers = what gets serialized where, incl. #0 segments?).
