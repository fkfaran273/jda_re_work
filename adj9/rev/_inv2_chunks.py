"""_inv2_chunks.py — chunk loop structure, work-area chaining, last writers."""
import gzip
import json
from collections import Counter, defaultdict

MAIN = 0x5450001000
REC_TOP = 1134

A = json.load(gzip.open("_inv2_row7_real.json.gz", "rt"))
wire = A["wire"]
blob = bytes.fromhex(A["blob"])
ops = [(e[0], e[1], e[3] + e[4] if e[0] == "E" else e[4], e[5] & 0xFFFFFFFF)
       for e in wire if e[2] == MAIN and e[0] in ("E", "Q")]
eseq = [(k, pc, o, v) for k, (kind, pc, o, v) in enumerate(ops) if kind == "E"]
rb = next(i for i, (k, pc, o, v) in enumerate(eseq) if pc == 0x119538)

# tokens of consecutive same-pc E
toks = []
s = rb
for k in range(rb + 1, len(eseq) + 1):
    if k == len(eseq) or eseq[k][1] != eseq[s][1]:
        lo = min(eseq[j][2] for j in range(s, k))
        hi = max(eseq[j][2] for j in range(s, k))
        toks.append([s, k, eseq[s][1], k - s, lo, hi])
        s = k

# chunk starts: tokens with pc 0x10a228
starts = [i for i, t in enumerate(toks) if t[2] == 0x10a228]
print("0x10a228 tokens:", len(starts))
prev = None
for si, sti in enumerate(starts):
    t = toks[sti]
    # what preceded: up to 3 tokens before
    ctx = [(toks[j][2], toks[j][3], toks[j][4], toks[j][5])
           for j in range(max(0, sti - 3), sti)]
    print("chunk start %d: ev%d abs=[%d..%d]  before: %s"
          % (si, t[0], t[4], t[5], ctx))

# end of last chunk -> what follows (next 40 tokens)
last = starts[-1]
nxt = [toks[j][2:6] for j in range(last, min(len(toks), last + 46))]
print("\nafter last chunk start:")
for (pc, n, lo, hi) in nxt:
    print("  pc=%#x n=%4d abs=[%d..%d]" % (pc, n, lo, hi))

# last writers of the record window + match vs body
state = {}
lastw = {}
for k, (kind, pc, o, v) in enumerate(ops):
    if kind == "E":
        state[o] = v & 0xFF
        lastw[o] = (pc, v & 0xFF)
ok = 0
bad = []
for p in range(144):
    o = REC_TOP + p
    pc, v = lastw.get(o, (None, None))
    bodybyte = blob[16 + p]
    if v == bodybyte:
        ok += 1
    else:
        bad.append((p, o, pc, v, bodybyte))
print("\nrecord-window final state == body[:144]: %d/144" % ok)
lw = Counter(pc for pc, v in lastw.values())
print("last-writer pcs:", dict(lw))
# digest window [1278..1310)?
dig_ok = 0
for p in range(32):
    o = 1278 + p
    pc, v = lastw.get(o, (None, None))
    if v == blob[160 + p]:
        dig_ok += 1
print("digest [1278..1310) final == blob[160:192]: %d/32" % dig_ok)
print("digest last writers:", Counter(lastw.get(1278 + p, (None,))[0]
                                      for p in range(32)))
