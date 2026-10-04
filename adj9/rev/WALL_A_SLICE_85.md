# Wall A - slice 85: #0 CAPTURED LIVE - the "nonce words" are heap pointers (2026-09-13)

Closes the open item of slices 80/84. `device/get0.py` + `get0.js`
(read struct+0x50, 144 B, at VM entry 0x100094 and fieldloop head
0x100114; fs17root, permissive, spawn-attach). One run, 7 signings in
the first 5 s: 7 vm samples, 84 fieldloop samples.

## Buffer integrity

All 84 fieldloop reads == their signing's VM-entry read: the buffer is
FILLED BEFORE the VM runs and never mutates during the field phase.
The vm-entry dump is authoritative.

## Structure (LE-u64 decode of a sample)

```
dw  0- 9   40 B run-stable data (random-shaped; dw4-5 = 0x808fc1eceab8e386
           == the fieldloop x9 constant seen live in slice 76 - cross-check)
dw 10-11   0x0b (11, descriptor count; same 0xb as vm x2) + 0
dw 12-25   SEVEN u64 HEAP POINTERS (0x00000071d387xxxx - a tight cluster of
           adjacent allocations: the descriptor array and its nodes)
dw 26-27   zero
dw 28-35   FOUR MTE-tagged pointers (0xb4000074…/0xb4000073…), symmetric
           P1 P2 P2 P1 - two objects each referenced twice
```

## Variance

- Across the 7 signings of ONE app run: dwords 0-11 IDENTICAL; only the
  11 pointer slots move (low halves shift with heap layout; high halves
  0x00000071 / 0xb40000 constant). 3 unique buffers from 7 signings
  (address reuse gives collisions).
- Across app runs (vs the fin_descs/whcap session): EVERYTHING differs.
- This also solves slice 84's tile mystery: in the whcap session all 11
  pointer slots held the same two tagged pointers alternating -
  (db50f44c b63798cc)=0xb63798ccdb50f44c and (dab7f51a b7d0992b)=
  0xb7d0992bdab7f51a - i.e. the "16-B block tiled 8.75x" was two MTE
  pointers tiled across the slots. Same structure, different heap state.

## Consequence (final answer to "can we get #0's nonce words")

Yes - and they are PROCESS MEMORY ADDRESSES, not secrets:
- per-signing variation = malloc addresses (why 80-ms-apart signings
  share 0/44 words - slice 80, and why no hash/PRNG fit existed);
- server-side: unverifyable by construction, consistent with slices
  81-83 (zero-filled #0 and replayed #0 both accepted, 200);
- for the generator: captured #0 replay or zero-fill both proven live;
  nothing left to synthesize. #0 is CLOSED.
