"""spn_kbnodes.py — extract the 64 initial KB node addresses and analyze
their read patterns in v4_reads.txt.

    python spn_kbnodes.py
"""
import json
import os
import struct
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

imm = json.load(open(os.path.join(WORK, "adj7s4_immruns.json")))["d20a0"]
kb_dwords = [int(x) for x in imm]
kb_index = {w: i for i, w in enumerate(kb_dwords)}

kb_writes = []
n = 0
with open(os.path.join(HERE, "v4_writes.txt")) as f:
    for ln in f:
        p = ln.split()
        n += 1
        if n > 40000:
            break
        a = int(p[0], 16)
        s = int(p[1])
        v = int(p[2], 16)
        if s == 4 and v in kb_index:
            kb_writes.append((n, a, kb_index[v]))
print("KB writes in first 40000 events:", len(kb_writes))
init = [(w, a, d) for w, a, d in kb_writes if d < 64]
print("init KB writes:", len(init))
node_of = {}
for w, a, d in init:
    node_of.setdefault(d, []).append((w, a))
addrs = []
for d in range(64):
    lst = node_of.get(d, [])
    first = lst[0] if lst else None
    addrs.append(first[1] if first else None)
    if d < 8 or d >= 60:
        print("  d%02d -> %s" % (d, [(hex(a), w) for w, a in lst[:2]]))
print("node addrs:", [hex(a) if a else None for a in addrs])

# ---- reads of these nodes ----
read_hits = defaultdict(list)   # addr -> [read event numbers]
n = 0
with open(os.path.join(HERE, "v4_reads.txt")) as f:
    for ln in f:
        p = ln.split()
        n += 1
        a = int(p[0], 16)
        if a in read_hits or True:
            if a in addrs:
                read_hits[a].append(n)
print("total reads", n)
tot = 0
for d, a in enumerate(addrs):
    c = len(read_hits.get(a, []))
    tot += c
print("total reads of KB nodes:", tot)
counts = [len(read_hits.get(a, [])) for a in addrs]
print("per-dword read counts:", counts)
# timeline: read-event numbers sorted -> find chunk windows
alle = sorted(e for a in addrs for e in read_hits.get(a, []))
print("first KB-node read at", alle[0] if alle else None,
      "last at", alle[-1] if alle else None)
gaps = sorted([(alle[i + 1] - alle[i], i) for i in range(len(alle) - 1)],
              reverse=True)[:20]
print("largest gaps:", gaps)
# order of node reads within first window (chunk 15 loop?)
first_win = [e for e in alle if e <= alle[0] + 40000]
seq = []
for e in first_win:
    for d, a in enumerate(addrs):
        if e in read_hits.get(a, []):
            seq.append((e, d))
            break
print("first 120 KB-node reads (event, dword):")
print([d for _, d in seq[:120]])
