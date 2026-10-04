"""blob_anatomy.py - map every blob word to its source in the capture.

Uses the app_reg.json capture (fresh signing, sec 1789971573) to establish
EXACTLY which memory/stream each of the 48 blob words comes from.
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "app_reg.json"), encoding="utf-8"))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


segs = segment([(st, n, v) for st, n, v in d["emits"]])
seg = segs[0]
byc = {}
for st, m in seg.items():
    byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])

print("seg0 streams by length:")
for L in sorted(byc):
    print("  len=%-4d x%d  first=%08x" % (L, len(byc[L]), byc[L][0][0]))

blob = bytes.fromhex(
    "645095aa156c490e2a67d7572b5b2e525c336a55be9462fb8b581861cc49cd1d"
    "023671bd9830b8dd8484fadb11c16f72ac2ca9a9601f52cbb1daa02355ab939"
    "11d07baae3f1a226f8f932a3aacc43aebeb067dedb6ce4075d38ad85dfa9a7183"
    "f114876a42896e9ab7084cdc6aaebbcad549fad2de7aafa7dd50936ac86b479a"
    "3be73e37b9a1ab7e87e8e84e8e415fb9cac01f3b52f645fc2e87e8a4393eb546"
    "9dc3ce42152aad5368de227c663f42802ab1b870918d2ef6202abe0760588dad")
bw = struct.unpack(">48I", blob)

# search each blob word in every stream of seg0
print()
print("blob word -> source stream (seg0)")
for i, w in enumerate(bw):
    found = []
    for L, streams in byc.items():
        for si, vs in enumerate(streams):
            if w in vs:
                found.append("len%d#%d[%d]" % (L, si, vs.index(w)))
    print("  blob[%2d] = %08x  <- %s" % (i, w, ", ".join(found[:4]) or "NOT IN SEG0"))
