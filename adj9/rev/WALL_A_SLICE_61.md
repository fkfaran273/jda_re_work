# Wall A - slice 61: worker inventory complete + 0x9c478 audit (2026-09-11)

## All 15 (+2 infra) workers mapped

| fn | size | role |
|---|---|---|
| `0xde24/0xe3a8/0xee74/0xf9b4` | 0x18-0x34 | verdict-bit setters (slice 58) |
| `0xe374/0xee40/0xddf0` | 0x34 | fold marker + bit (slice 58) |
| `0x15384` | 0x1c0 | fold + malloc + self?-call (marker decrypt helper) |
| `0xd868` | 0x348 | sub-dispatcher (slice 59) |
| `0x1bcc4` | 0x550 | JNI + 0x9c478 + malloc (slice 60) |
| `0xde3c` | 0x538 | fold + verdict R/W + fan-out (slice 60) |
| `0x8c98` | 0x9c4 | env checks + fold + 0xbb548-use (0x94f8) + adrp strings |
| `0x1c920` | 0xb24 | dispatcher + JNI + env check + fold-adjacent |
| `0x15590` | 0x1a7c | mega-fn: 0xbb548-use x2 (0x16034/0x163b8), env x3, fold |
| `0xe740` | 0x700 | 26-marker machine (known) |
| `0x8c98-helpers` | — | `0x8c30/0x8c64/0xd0838/0xd3ef8` infra |

## `0x9c478` audit (10 callers, frame-slot args throughout)

Generic native helper (hub `0x9c580`, JNI idx1368-call + `0x9ad54` +
`0x9afa4`): called with caller-frame slots + regs at all 10 sites
(`0x1bf84, 0x1d2f8, 0x9103c, 0x9351c, 0xbbb10, 0xd20f0, 0xd3308, 0xd4b3c,
0xd67a8, 0x12c6a0`). NOT a plain memcpy (own dispatcher + JNI). Exact
encode/fetch role per site still needs its hub walk (same wall: state
regs + runtime values).

## Net of "do all"

Done: every named target lifted to role+address+callers (feeders, workers,
builders, assembly, JNI census, hub prologue, master struct, smali flow,
fetch program, time formats, cert). Open (all runtime-gated): exact values
per slot (#0/others/ns), hub walks needing live regs (ba674, bb668-visit,
9c478-hub, orchestrator mazes), assembly visit order + concat, parse.
