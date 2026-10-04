"""seg27_multi.py - does seg27 hold >1 signing? list every 48/36/97-word
stream head in the segment + header-law seconds for each 48-word head.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))


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
for cnt in sorted(byc):
    print("n=%-3d count=%d" % (cnt, len(byc[cnt])))
    for vs in byc[cnt]:
        print("   head=%s" % " ".join("%08x" % v for v in vs[:4]))
# header-law seconds for each 48-word head in window 1789914400..1789914700
print("--- header inversion (window 1789914400..1789914700) ---")
for vs in byc.get(48, []):
    hdr = b(vs[:4])
    secs = [s for s in range(1789914400, 1789914700) if make_header(s) == hdr]
    print("  %s -> %s" % (" ".join("%08x" % v for v in vs[:4]), secs or "NONE"))
# same for 97-word claims created_at
import re
for vs in byc.get(97, []):
    cl = b(vs).decode("latin1", "replace")
    m = re.findall(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z[+-]\d{4}", cl)
    print("  claims97 created_at:", m)
