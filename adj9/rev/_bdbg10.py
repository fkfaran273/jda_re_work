"""_bdbg10.py — differential probes at the in[] level.

Probe A: row 7 region with d2 ^= 0xFFFFFFFF  (is the map d2-dependent?)
Probe B: row 7 region with d0 word0 ^= 0xFFFFFFFF (linear spread of W0)
Compare in[514..658) arrays vs the baseline row 7 run.
"""
import json
import os
import struct
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fin_vm2 import FinEx
from vm_taint import corpus_row_descs, corpus_row
import vm_taint as VT

ROW = 7
SINK = 0x5500000000

base_descs = [list(t) for t in corpus_row_descs(ROW)]
second, cap = corpus_row(ROW)


def run(descs, tag):
    ex = FinEx(second, [tuple(t) for t in descs])
    ex.__dict__["_wire_log"] = []
    t0 = time.time()
    st = ex.run(max_steps=60_000_000)
    WL = ex.__dict__["_wire_log"]
    W = defaultdict(list)
    for ev in WL:
        if ev[0] == "E":
            W[(ev[2], ev[3] + ev[4])].append(ev[5])
    inb = bytes(W[(0x5450001000, 620 + i)][-1] for i in range(514, 658))
    # blob check
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva, n)] = v & 0xFFFFFFFF
    blob = b"".join(struct.pack(">I", last.get((SINK, k), 0)) for k in range(48))
    print("%s: status=%s steps=%d %.0fs blobmatch=%s"
          % (tag, st, ex.steps, time.time() - t0, blob == cap), flush=True)
    return inb, blob, WL


# baseline from saved json
base_in = bytes(json.load(open("_bdbg8_row%d.json" % ROW))["in_vals"][str(i)]
                for i in range(514, 658))

# probe A: flip d2
dA = [list(t) for t in base_descs]
bi = VT.VA_ORDER.index(2)
w = dA[bi][2]
dA[bi][2] = bytes(x ^ 0xFF for x in w)
inA, blobA, WLA = run(dA, "probeA(d2flip)")

# probe B: flip d0 word 0
dB = [list(t) for t in base_descs]
bi = VT.VA_ORDER.index(0)
w = dB[bi][2]
dB[bi][2] = bytes(x ^ 0xFF for x in w[:4]) + w[4:]
inB, blobB, WLb = run(dB, "probeB(d0w0flip)")

json.dump(WLA, open("_bdbg10_wirelogA.json", "w"))
json.dump(WLb, open("_bdbg10_wirelogB.json", "w"))

d = json.load(open("_bdbg8_row%d.json" % ROW))
key = d["pre"]
print("\nbaseline in:", base_in[:32].hex())
print("probeA   in:", inA[:32].hex())
print("probeB   in:", inB[:32].hex())
diffA = bytes(a ^ b for a, b in zip(base_in, inA))
diffB = bytes(a ^ b for a, b in zip(base_in, inB))
print("\ndiffA (d2 flip):", diffA.hex())
print("diffB (w0 flip):", diffB.hex())
# multiset comparison (permutation?)
from collections import Counter
print("\nin[] multiset preserved under d2 flip:",
      Counter(base_in) == Counter(inA))
print("in[] multiset preserved under w0 flip:",
      Counter(base_in) == Counter(inB))
nzA = [i for i in range(144) if diffA[i]]
nzB = [i for i in range(144) if diffB[i]]
print("d2flip changed in[] at offsets:", nzA[:50], "count", len(nzA))
print("w0flip changed in[] at offsets:", nzB[:50], "count", len(nzB))
