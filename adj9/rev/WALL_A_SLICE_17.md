# Wall A — slice 17: final assembly `0xbb548`, call level (2026-09-11)

Fn `0xbb548–0xbbbf8` (~1968 B, ~1000 insns, frame `0x120`, next fn `0xbbbf8`).
O-LLVM flattened, hub **`0xbb668`** (15 block-ends converge). No direct crypto;
5 calls:

| site | target | role (verified) |
|---|---|---|
| `0xbb914` | `bl` PLT `0x148b10` (malloc) | `malloc(*[x29−0x28] + 1)`; preceding `strb wzr,[x10+x8]` = NUL terminator → C-string dup (length-prefixed +1, likely a claim/time string) |
| `0xbb9c8` | `blr x8`, `[x8+0xb8]` | JNI `NewByteArray`: func offset `0xb8` = index 23 ✓; `x0=env([x29−0x30])`, `x1=len([sp+0x20])` |
| `0xbba34` | `bl 0xba4a8` | internal builder `(x0=x20, x1, x2, x3, x4=x29−0x18)` |
| `0xbbb10` | `bl 0x9c478` | internal builder `(x0=x20, x2=[x29−0x18], x3=x29−0x20, x4=x29−0x28)` |
| `0xbbb84` | `blr x8`, `[x8+0x550]` | JNI `SetByteArrayRegion`: offset `0x550` = index 170 ✓; `(env, array=x25, start=[x29−0x40], …)` → 192-B Java byte[] out |

So the blob is assembled as: builders fill native buffers → `NewByteArray(len)`
→ `SetByteArrayRegion` → return. The remaining unknowns are ordering
(hub-visit sequence of the 5 calls), the `len` value materialized at
`[sp+0x20]` (expect 192 = `0xC0`: 16 header + 176 body — to be confirmed, not
assumed), the `x25` array flow, and which stream/sections feed `0xba4a8` /
`0x9c478` (header-prepend position lives here).

## How to close it (mechanical, slice-2 tooling)

Run `rev/unflatten.py` + `rev/walk_machine.py` on hub `0xbb668` (same
procedure as the `0x24a40` machine: state reg, token/block map, visit order),
then read off: call order, `[sp+0x20]` dataflow, `x20`/`x25` provenance,
`[x29−0x18]/−0x20/−0x28` slot roles. No new RE technique — pure application.

## Scoreboard update

Proven since slice 7: header law, sites, field loop (62/62, real values),
LENQ/OUTLEN/EMIT exact, allocators, stream struct, cert (R1) + in-path digest
(R2), golden pack, verifier 114/114, diffusion-total (differentials dead).
Owed: `0xbb548` visit order (this slice specs it) + 7 input payloads (R4) +
`0xba4a8`/`0x9c478` internals. Then: 38-match → claim loop → done.
