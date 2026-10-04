"""seg_census.py - full segment census of the run7 click capture.

1. every segment's stream sizes; which segments hold 36w / 48w / 17w / 97w.
2. every 48w stream head -> header inversion (window around claims ws).
3. 36w stream heads per segment (same signing or mixed?).
"""
import json, os, struct, sys, calendar, datetime, re
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
print("segments: %d" % len(segs))
for k, s in enumerate(segs):
    sizes = sorted(len(v) for v in s.values())
    flags = []
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) == 36:
            flags.append("36:%08x" % vs[0])
        if len(vs) == 48:
            flags.append("48:%08x" % vs[0])
        if len(vs) == 17:
            flags.append("17:%08x" % vs[0])
        if len(vs) in (97, 90):
            flags.append("%d:%08x" % (len(vs), vs[0]))
    if any(x.split(":")[0] in ("36", "48", "17", "97", "90") for x in flags):
        print("seg %d sizes=%s %s" % (k, sizes, flags))
# header inversion for every 48w head, window around click ws
print("--- 48w header inversion (window 1789914400..1789914750) ---")
hdrs = {s: make_header(s) for s in range(1789914400, 1789914751)}
for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) == 48:
            hit = [sec for sec, h in hdrs.items() if b(vs[:4]) == h]
            print("seg %d 48w head=%s -> %s" %
                  (k, " ".join("%08x" % v for v in vs[:4]), hit if hit else "NO MATCH"))
