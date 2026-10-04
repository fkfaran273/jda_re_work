# Wall A - slice 41: workhorse walks 44, body layout sequential (2026-09-11)

Route: dispatch=400 -> 0x100a2c/0x101098 chain -> 0x12924c (forced 387,
exact like 742) -> workhorse head 0x12a760. OUTLEN forced 44 at 0x12a868
(all INJECTED).

## Workhorse (0x12a880 loop): 44 iterations, sequential output

Per-dword LENQ -> EMIT with counter w23 = 0..43, all 44 EMITs landing on
ONE stream at indices 0..43 IN ORDER (MAIN `[CTX+8]` in our run - x26
never advances here; natively x26 may select per-section streams for the
multi-stream concat of slice 6.7). Values all zero (placeholder LENQ reads
- real claims would flow with real workspace). Post-loop: 0x12aa08, maxpc
0x12aa30, exit-clean.

## Body layout (structural)

44 sequential dwords = 176 B = THE BODY, one stream, index = counter.
Header (4, MAIN[0..3] per slice 39) and body (44) share the MAIN sink in
this configuration - natively separated by x26-advance and joined at
assembly (0xbb548 concat, still owed). With real LENQ hits, these 44 slots
carry the whitened claims (H as opaque tag among them per descriptor
0x20); positions are counter-determined (order-stable), values
input-determined.

## Remaining for body-open

Real LENQ values into the 44 slots (R4 #0 encoding - the ONLY content
unknown on this path; x26-advance rule from a second stream-select
observation) + assembly concat order + parse. The engine needs no more
reverse-engineering: 44-iteration structure, counter/index/value roles,
skip-on-zero and reseed paths all verified live.
