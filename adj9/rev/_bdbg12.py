"""_bdbg12.py — measure the fixed layer->body operator P via marker probes.

The d0 byte area [514..658) holds a RECORD (flags + d0 head rev16 + d2 LE +
cert + region hash + ...).  The body words 4..39 = the record bytes after the
fixed 15-sweep whitening + shuffles.  Probe with zero region and marker
region to recover the byte map:  body[m] = layer[sig(m)] ^ c[m].
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
    t0 = time.time()
    st = ex.run(max_steps=60_000_000)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva, n)] = v & 0xFFFFFFFF
    blob = b"".join(struct.pack(">I", last.get((SINK, k), 0)) for k in range(48))
    print("%s: status=%s steps=%d %.0fs" % (tag, st, ex.steps,
                                            time.time() - t0), flush=True)
    return blob


def setd(descs, bi, data):
    d = [list(t) for t in descs]
    i = VT.VA_ORDER.index(bi)
    d[i][2] = data
    return d


# probe Z: all-zero region
dz = setd(base_descs, 0, b"\x00" * 144)
dz = setd(dz, 2, b"\x00" * 4)
dz = setd(dz, 4, b"\x00" * 32)
blobZ = run(dz, "probeZ")

# probe M: marker region — d0 words give 144 distinct serialized bytes,
# d2 distinct, d4 distinct
d0m = b"".join(bytes([(4 * i + 1) & 0xFF, (4 * i) & 0xFF,
                      (4 * i + 3) & 0xFF, (4 * i + 2) & 0xFF])
               for i in range(36))
d2m = bytes([0xA0, 0xA1, 0xA2, 0xA3])
d4m = b"".join(bytes([(0xB0 + 4 * i + 1) & 0xFF, (0xB0 + 4 * i) & 0xFF,
                      (0xB0 + 4 * i + 3) & 0xFF, (0xB0 + 4 * i + 2) & 0xFF])
               for i in range(8))
dm = setd(base_descs, 0, d0m)
dm = setd(dm, 2, d2m)
dm = setd(dm, 4, d4m)
blobM = run(dm, "probeM")

bZ = struct.unpack(">44I", blobZ[16:])
bM = struct.unpack(">44I", blobM[16:])

# byte arrays of body words 4..39 (the record area)
zB = b"".join(struct.pack(">I", w) for w in bZ[:36])
mB = b"".join(struct.pack(">I", w) for w in bM[:36])
diff = bytes(a ^ b for a, b in zip(zB, mB))
print("\nbodyZ[0..48):", zB[:48].hex())
print("bodyM[0..48):", mB[:48].hex())
print("diff[0..48) :", diff[:48].hex())
print("diff[48..96):", diff[48:96].hex())
print("diff[96..144):", diff[96:144].hex())

json.dump({"blobZ": blobZ.hex(), "blobM": blobM.hex()},
          open(os.path.join(HERE, "_bdbg12_probes.json"), "w"))
print("saved _bdbg12_probes.json")
