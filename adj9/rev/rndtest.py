import struct
import json
import sys

sys.path.insert(0, ".")
from vm_final import Random3

t = json.load(open("..\\device\\triples_tail7.json"))
Hws = {}
targets = {}
for tag, hk in [("sess", "sess_H"), ("click", "click_H")]:
    Hws[tag] = struct.unpack(">8I", bytes.fromhex(t[hk]))
targets = {"sess": 0x3465D635, "click": 0x0C5BC6BE}
H1 = Hws["sess"]
cands = {}
for i, a in enumerate(H1):
    cands["H%d" % i] = a
for i in range(8):
    for j in range(i + 1, 8):
        cands["Hx%d%d" % (i, j)] = (H1[i] ^ H1[j]) & 0xFFFFFFFF
    cands["Ha%d" % i] = (H1[i] + 0x9E3779B9) & 0xFFFFFFFF
for name, seed in cands.items():
    r = Random3(seed)
    draws = [r.next() & 0xFFFFFFFF for _ in range(40)]
    if targets["sess"] in draws:
        print("sess hit:", name, "at draw", draws.index(targets["sess"]))
print("done")
