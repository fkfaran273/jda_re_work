"""find_blob5.py - locate the blob + second in the fresh app_dump (pid 14175).

Approach: build second->header4 dict for the whole capture window (one make_header
call per second, dict lookup per window), then scan every stream's consecutive
4-slot windows. The blob's first 4 words ARE Random3(second) (slice 121).
"""
import datetime
import json
import os
import struct
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))

# capture ran 00:12-00:13 UTC on 2026-09-21; claims re-read at 00:15:23.
# cover a generous window either side.
# created_at 2026-09-21T00:15:23.352Z+0530 -> UTC 2026-09-20 18:45:23 -> epoch 1789929323
base = 1789929323
lo, hi = base - 60, base + 120
print("window", lo, "...", hi, flush=True)

hdr2sec = {}
for s in range(lo, hi):
    hdr2sec[make_header(s)] = s
print("header table:", len(hdr2sec), flush=True)

def scan(store, tag):
    hits = []
    for a, m in store.items():
        items = sorted(m.items())
        for i in range(len(items) - 3):
            # require consecutive slot indices
            if items[i+3][0] - items[i][0] != 3:
                continue
            ws = tuple(items[i+k][1] for k in range(4))
            key = struct.pack(">4I", *ws)
            if key in hdr2sec:
                hits.append((a, items[i][0], hdr2sec[key], ws))
    print(tag, "hits:", len(hits), flush=True)
    for a, slot, s, ws in hits:
        print("  %s slot=%d sec=%d head=%s" % (a, slot, s, ["%08x" % x for x in ws]), flush=True)
    return hits

em = defaultdict(dict)
for addr, n, v in d["emits"]:
    em[addr][n] = v
lq = defaultdict(dict)
for addr, n, v in d["lenq"]:
    lq[addr][n] = v

hits = scan(em, "EMIT") + scan(lq, "LENQ")
if hits:
    a, slot, sec, ws = hits[0]
    src = em if (a, slot, sec, ws) in scan(em, "EMIT2") else lq
    m = src[a]
    words = [m.get(slot + i) for i in range(48)]
    print("words48 complete:", all(x is not None for x in words), flush=True)
    blob = struct.pack(">48I", *[x or 0 for x in words])
    json.dump({"second": sec, "blob": blob.hex(), "stream": a, "slot": slot},
              open(os.path.join(HERE, "fin5_blob.json"), "w"))
    print("saved fin5_blob.json", flush=True)
