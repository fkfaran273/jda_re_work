# Wall A - slice 32: guided descent - passes chain by dispatch values (2026-09-11)

Fault hook in vm_final.py (POP at 0x100570 takes _force_val once).
INJECTED label on every such run (not real inputs).

## 1. Router chain (disasm + forced runs)

Dispatch at 0x100554 routes by value: <0x2d to 0x128838, ==0x2d to 0x128990,
>=0x37e to 0x100710, >=0x19f to 0x100830, >=0xeb to 0x100a2c, >=0xbb to
0x100db0, <0x7d to 0x128fc0, <0x99 to 0x1293c8, ==0x99 to 0x1005c4 (PUSH 6),
else to 0x12a8b4 (PUSH 109 seeder + loop-back). Case 0x128838 guards
w0==0x11 else falls to the seeder too. Case 0x1293c8 re-checks w0==0x7d
(125), else loop-back.

## 2. force=125: two natural passes (73 qops, 1615 steps, +84 pcs)

Dispatch 1 (injected 125) -> 0x1293c8 gate passes -> case body -> seeder
-> pass 2 -> dispatch 2 NATURAL value 4 -> 0x128838 -> guard fails ->
seeder -> pass 3 -> isEmpty starve. Passes chain by queue leftovers; each
pass's dispatch value routes the next. Forced sweep (45/100/124/126/130/
150/153/200/400/700) routes every value correctly; none reaches the header
loop (needs SUSTAINED descent with live queue, i.e. real workspace hits).

## 3. Dead gateway retracted-and-closed

The 0x128eec cmp-742 cluster (slice 31-era hypothesis): no outside entries,
no fall-through into it (0x128e8 is unconditional exit branch), same
O-LLVM junk family as the verified SM4 opaque predicates. The 725/742
numbers are decoys. Header entry is ONLY 0x128ef0 (from that dead cluster)
plus fall-through 0x12a1f4-0x12a200 (reached from the 0x129bb4 downward
flow, i.e. from inside a deep case). Net: header path = sustained descent,
not a threshold.

## 4. What this changes

The emulator now demonstrably walks multi-pass trajectories with evolving
dispatch (125 -> 4 -> starve on placeholders). Real inputs steer each
pass's dispatch; the day a run chains passes without starving, it is
converging. Monitor: dispatch values per pass + nrand.
