# Wall A - slice 46: one merge stream; 258-pass routing census (2026-09-11)

## x26 advances exactly once (multi-stream theory dead)

Full-VM scan: x26 written ONLY at `0x100284` (x26=x20) and the return-path
`0x100338`; single advance `ldr x1,[x26,#8]!` (CTX -> CTX+8); every other
use is a plain read. So ALL merge/header EMITs with sink=[x26] land in ONE
stream: MAIN `[CTX+8]`. Slice-6.7 multi-stream concat is withdrawn for the
VM body (field sinks + MAIN + queues are the whole live set; assembly must
read header/body both out of MAIN or its sections).

## 258-pass sustained run (force=742 + counter supply)

40,630 steps, nrand 8 (first pass), MAIN 524 dwords, writer clean.
Dispatch census over 258 decisions: 253x value 0, 3x value 1, 1x forced
742, 1x 0x25. Gateway/header/workhorse pcs: hit once each (forced pass
only). Every natural pass routes seeder/short cases and drains.

## Verdict

Placeholder workspace yields only 0/1 routing values, forever. Real
routing needs real LENQ/OUTLEN hits = real #0 TOPs/acc = real content.
No experiment left on the routing side; the content side (R4 #0 encoding +
struct values + ns) is the entire remainder, then assembly offsets +
parse. Monitor set is complete and stable (dispatch census, gateway pcs,
nrand, stream totals, writer).
