# Wall A - slice 56: register audit + handoff scan negative (2026-09-11)

## Register provenance at `0xdbb64` (full hub backward slice)

x0-x4 as established (slice 55). x20-x25, x27-x28 = maze CONSTANTS
(movk ladders at `0xdb2xx`), x26 untouched (caller leftover). NO stream
pointer rides registers - eliminated by exhaustion (every reg accounted).

## Static handoff scan: negative

adrp+store chains into fixed addresses: ZERO in VM (`0x100094-0x12aa48`),
stamp (`0x12cb74-0x12de58`), and `0xba4a8` ranges. Streams do not pass via
`.data`/`.bss` globals through this pattern ( Solo remaining forms:
register-indirect chains, or no handoff at all).

## Re-derive hypothesis (new, falsifiable)

`0xbb548(levelCell, JNIEnv, MAP, "environment", outCell)` may RE-DERIVE
rather than consume: MAP + environment string in, buffer out (via
`0xba4a8` claim-fetch + `0x9c478` helpers + NewByteArray-site `0xa8324`
elsewhere?). The VM streams would then be an intermediate (verifier?
header-only path?) rather than the assembly input. Test: does any path
from `0xdbb64` return WITHOUT the VM having run (nSign with cached/no-VM
fast path)? The JCA trace shows Mac-then-nSign per signing; a VM-less
nSign would still emit blobs (observable in probe pairs: h-zero bodies
valid => VM ran (whitening present)). Counter-test via B-blobs:
deterministic replays would reveal caching. Open experiment, low cost.
