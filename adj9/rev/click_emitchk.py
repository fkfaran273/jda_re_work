"""click_emitchk.py - EMIT-side cross-check for the click descriptors (LENQ
has no timestamps, so EMIT is the only plane attributable to seg27).

1. Every word of seg27's 36w/8w/97w streams: emitted in ANY other segment?
   (if yes, the capture mixed signings and the FinEx inputs are polluted.)
2. EMIT sizes profile of the whole capture; segments with 17w streams.
3. The click blob's own LENQ reads: which (stream,slot) return blob words?
"""
import json, os, struct, sys
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
SEC = 1789914579


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


segs = segment([(st, n, v) for st, n, v in d["emits"]])
print("segments: %d" % len(segs))
seg = segs[27]
byc = {}
for st, m in seg.items():
    byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])
z36, z8, blob, claims = byc[36][0], byc[8][0], None, byc[97][0]
for vs in byc[48]:
    if b(vs[:4]) == make_header(SEC):
        blob = vs
        break
print("seg27: 36=%08x 8=%08x blob=%08x claims97" % (z36[0], z8[0], blob[0]))
# 1. cross-segment emission of descriptor words
occ = Counter()
first = {}
for k, s in enumerate(segs):
    for st, m in s.items():
        for i, v in m.items():
            occ[v & 0xFFFFFFFF] += 1
            first.setdefault(v & 0xFFFFFFFF, k)
for nm, vs in (("#0", z36), ("#4", z8)):
    multi = sorted(set(v & 0xFFFFFFFF for v in vs if occ[v & 0xFFFFFFFF] > 36))
    print("%s words emitted >36x anywhere: %d/=%d e.g.%s" %
          (nm, len(multi), len(vs), ["%08x" % v for v in multi[:6]]))
multi_c = sorted(set(v & 0xFFFFFFFF for v in claims if occ[v & 0xFFFFFFFF] > 97))
print("claims words emitted >97x anywhere: %d/97" % len(multi_c))
# 2. segments with 17w streams + sizes
print("--- segments holding a 17-length stream ---")
for k, s in enumerate(segs):
    for st, m in s.items():
        if len(m) == 17:
            vs = [m[i] for i in sorted(m)]
            print("  seg %d head=%s sizes=%s" % (k, " ".join("%08x" % v for v in vs[:3]),
                                                 sorted(len(v) for v in s.values())))
# 3. blob words in LENQ: which streams?
L = d.get("lenq", [])
bset = set(x & 0xFFFFFFFF for x in blob)
hit = Counter()
for e in L:
    if (e[2] & 0xFFFFFFFF) in bset:
        hit[e[0]] += 1
print("--- LENQ streams returning seg27 blob words ---")
for st, c in hit.most_common(10):
    print("  %s x%d" % (st, c))
