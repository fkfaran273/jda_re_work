# Wall A - slice 68: small-tail battery null, assembly harness next (2026-09-11)

## Small-tail battery (`r4_small.py`, kept? no - one-off)

#0-tail + #2/#6/#7 ∈ {0, 1, 36} with kv body: all identical (1375 steps,
acc 176, offs 176 + 1 nonzero, no gateway). Small tails alone change
nothing - they matter only inside a live gateway path (OUTLEN-selected
streams), which itself needs staged gates. Prediction stands unfalsified
(it requires the path it would validate).

## Assembly harness (specified, not built)

`0xbb548(levelCell, JNIEnv, MAP-jobject, "environment", outCell)` needs its
own emulator run: flattened (hub `0xbb668`, arg-dependent route per slice
18) with concrete arg CLASSES (level int 31, JNIEnv opaque Walker?, MAP =
real 50-map contents for claim re-derivation?, outCell = scratch). The VM
streams question (consume vs re-derive, slice 56) gets settled by which
args the assembly actually reads: MAP-reads (CallObjectMethod sites in
0xbb548 range) vs stream/global reads.

## Net

Static + staged work is complete through the workhorse with correct
supply patterns; content batteries (~110 runs) all flat on natural
trajectories; gateway/header need staged gates + live workspace. Next
mechanical items: assembly harness build, then parse.
