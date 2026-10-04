"""_bdbg8.py — verify the final whitening sweep law and extract pre-final values.

Law hypothesis: final sweep (site 0x111c68, the last writer of every body byte)
  out[i] = in[i] ^ 0x55 ^ fb[i]
  fb[i]  = section[i-33]   (finalized value: blob byte for i-33 >= 514,
                            key block/header before that)
Extract in[i] = out[i] ^ 0x55 ^ sec[i-33] and compare with the known d0.
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

ROW = int(sys.argv[1]) if len(sys.argv) > 1 else 7

descs = corpus_row_descs(ROW)
second, cap = corpus_row(ROW)
ex = FinEx(second, descs)
ex.__dict__["_wire_log"] = []
t0 = time.time()
st = ex.run(max_steps=60_000_000)
WL = ex.__dict__["_wire_log"]
print("row %d status=%s steps=%d %.0fs events=%d"
      % (ROW, st, ex.steps, time.time() - t0, len(WL)), flush=True)

writers = defaultdict(list)      # (sva, abs) -> [(si, pc, v)]
reads_by_si = []
for si, ev in enumerate(WL):
    if ev[0] == "E":
        writers[(ev[2], ev[3] + ev[4])].append((si, ev[1], ev[5]))
    elif ev[0] == "Q":
        reads_by_si.append((si, ev[1], ev[2], ev[3] + ev[4], ev[5]))


def final_writer(sva, absidx):
    lst = writers.get((sva, absidx))
    return lst[-1] if lst else None


BASE = 620
# body byte positions and final values
body = {}
finalpc = {}
pre = {}
for i in range(460, 658):
    w = final_writer(0x5450001000, BASE + i)
    if w is None:
        continue
    si, pc, v = w
    pre[i] = v
    if i >= 514:
        body[i] = v
        finalpc[i] = pc

pcs = defaultdict(list)
for i, pc in finalpc.items():
    pcs[pc].append(i)
print("final writer pcs:", {hex(k): (len(v), min(v), max(v)) for k, v in pcs.items()})

# for each final write, find the reads just before it (within 40 events):
#   the in-place read (same position) and the fb read
sec_final = dict(pre)
in_vals = {}
law_ok = 0
law_bad = []
fb_map = {}
for i in sorted(body):
    w = final_writer(0x5450001000, BASE + i)
    si, pc, v = w
    # reads within 40 events before si
    rd = [(s, p, a, vv) for (s, p, sv, a, vv) in reads_by_si
          if si - 45 < s < si and sv == 0x5450001000]
    inplace = [r for r in rd if r[2] == BASE + i]
    fbs = [r for r in rd if r[2] != BASE + i]
    if not inplace:
        law_bad.append((i, "no-inplace-read", rd[-3:]))
        continue
    iv = inplace[-1][3]
    # fb read: the last non-self read before the write
    if not fbs:
        law_bad.append((i, "no-fb-read", None))
        continue
    fsi, fpc, fabs, fv = fbs[-1]
    fb_pos = fabs - BASE
    fb_map[i] = (fb_pos, fv, fpc)
    # check out = in ^ 0x55 ^ sec[fb_pos]
    fbv = sec_final.get(fb_pos)
    if fbv is None:
        law_bad.append((i, "fb-unwritten", fb_pos))
        continue
    pred = iv ^ 0x55 ^ fbv
    in_vals[i] = iv
    if pred == v:
        law_ok += 1
    else:
        law_bad.append((i, "mismatch", (iv, fbv, v, pred)))

print("law ok: %d / %d" % (law_ok, len(body)))
for b in law_bad[:12]:
    print("  bad:", b)

# fb position offsets
offs = defaultdict(int)
for i, (p, v, pc) in fb_map.items():
    offs[i - p] += 1
print("fb offset (i - fb_pos) histogram:", dict(offs))

# fb read pcs
fpcs = defaultdict(int)
for i, (p, v, pc) in fb_map.items():
    fpcs[pc] += 1
print("fb read pcs:", {hex(k): v for k, v in fpcs.items()})

json.dump({"in_vals": in_vals, "fb_map": fb_map,
           "out": body, "pre": pre},
          open(os.path.join(HERE, "_bdbg8_row%d.json" % ROW), "w"))
print("saved _bdbg8_row%d.json" % ROW)
