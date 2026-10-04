# Wall A - slice 34: header primitive byte-exact in-emulator (2026-09-11)

Force-walk (INJECTED dispatch=742) qlog audit of the header loop
(0x12a2ec MKITER(4) + 0x12a2f8 loop):

## Draws == device stream, XOR == real header word

- PUSH A = 1675440164 == Random3(1789123783) draw #1, EXACT.
- PUSH B = 709149083 == draw #2, EXACT.
- A^B = 0x4999f1bf == golden fresh blob header dword 0 (`4999f1bf...`), EXACT.
- MKITER count POP = 4 (0x12a2d0 takes the PUSH(4)) - loop bound correct.

So srand seed, draw order, XOR, count are all byte-exact vs the device on
the real code path. The header the device emits is fully explained.

## Structural deficit: -1 queue element per iteration

Per iteration: PUSHes(A,B,X,c+1) = 4, POPs(A,B,len,arg,counter) = 5. The
len/arg/counter chain must be supplied below the working set (initial
counter seed 0 + 8 len/arg values over 4 iters). Ours starves at the 5th
pop (0x12a3e4, EMPTY) after 2 draws; EMIT never fires. Natively these come
from the gateway path's leftovers (LENQ-fed values with real workspace).
No model bug: same code, unfed queue.

## Remaining, in order

Queue supply for iterations 1-4 (8 len/arg + counter seed from a live
gateway path = real workspace values = R4 inputs) -> 4 header dwords EMIT
-> workhorse (0x12a880) copies/whitens 44 body dwords -> cases ->
0xbb548 assembly (NewByteArray + SetByteArrayRegion) -> 192 B -> parse ->
claim loop. The walk harness (force + preload) reaches every stage; only
the supply is missing.
