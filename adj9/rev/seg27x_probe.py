"""seg27x_probe.py - cheap decisive analysis BEFORE the next FinEx battery.

1. Where do seg27's 17w stream dwords sit inside the seg27 blob?
   (contiguous run => output section; scattered/absent => input candidate)
2. EMIT 97w claims vs LENQ 97-read claims stream: identical word-by-word?
3. Full singles inventory + claims head/tail + #7 candidates.
4. Blob membership of CONST9/CONST8/d2 (inputs should NOT be in the blob).
"""
import json, os, struct, sys
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
seg = segs[27]
byc = {}
for st, m in seg.items():
    byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])
blob = [vs for vs in byc[48] if b(vs[:4]) == make_header(SEC)][0]
claims = byc[97][0]
w17 = byc[17][0]
print("seg27 sizes:", sorted(len(v) for v in seg.values()))
print("singles:", ["%08x" % vs[0] for vs in byc[1]])
print("17w:", " ".join("%08x" % v for v in w17))
# 1. locate w17[:16] in blob
hits = [i for i in range(48 - 15) if blob[i:i + 16] == w17[:16]]
print("17w-content contiguous run at blob word offsets:", hits if hits else "NONE")
per = sorted(set(i for i in range(48) for w in w17[:16] if blob[i] == w))
print("blob words equal to some 17w dword: %d/48 at %s" % (len(per), per[:50]))
# 2. LENQ claims vs EMIT claims
L = d.get("lenq", [])
lq = {}
for e in L:
    lq.setdefault(e[0], []).append((e[1], e[2] & 0xFFFFFFFF))
lq_claims = None
for st, reads in lq.items():
    if len(reads) == 97 and str(st).endswith("36c0"):
        lq_claims = [v for n, v in sorted(reads)]
        break
print("LENQ claims stream found:", lq_claims is not None)
if lq_claims is not None:
    diffs = [(i, "%08x" % (a & 0xFFFFFFFF), "%08x" % (c & 0xFFFFFFFF))
             for i, (a, c) in enumerate(zip(lq_claims, claims)) if (a & 0xFFFFFFFF) != (c & 0xFFFFFFFF)]
    print("LENQ-vs-EMIT claims diffs: %d/97 %s" % (len(diffs), diffs[:8]))
print("claims head:", " ".join("%08x" % v for v in claims[:4]))
print("claims tail:", " ".join("%08x" % v for v in claims[-6:]))
print("claims tail ascii:", b(claims[-8:]))
# 4. inputs in blob?
bb = b(blob)
for nm, hx in (("CONST9", "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"),
               ("CONST8", "bffffffffffffd1f0007000000000000"),
               ("d2", "cd9d3a91")):
    raw = bytes.fromhex(hx)
    print("%s in blob: %s" % (nm, raw in bb))
print("blob head:", " ".join("%08x" % v for v in blob[:4]))
print("blob tail:", " ".join("%08x" % v for v in blob[-4:]))
