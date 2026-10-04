"""app_seg.py - segment the APP'S OWN signing capture and read the role table.

Per slice 122: the EMIT plane must be segmented by the pos-0 rule (sink addresses are
recycled), then each segment is read as (count, first words) and matched against the
golden role table: #10={90} claims-ASCII | #0={36 + 16-byte tile x8} | #4={8} |
#9={5} | #8={4} | #2,#5,#6,#7={1}.  The decisive questions: is a 5-word #9 present
for the app's own signing, and can FinEx reproduce the emitted blob from the same
segment's streams (BE byte order, slice 121)?
"""
import base64
import calendar
import datetime
import json
import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
print("nemit=%d nlenq=%d nblobs=%d" % (d["nemit"], d["nlenq"], len(d.get("blobs", []))))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


EM = [(st, n, v) for st, n, v in d["emits"]]
segs = segment(EM)
sizes = sorted((sum(len(v) for v in s.values()), k) for k, s in enumerate(segs))
print("segments: %d ; 10 largest sizes: %s" % (len(segs), [s for s, _ in sizes[-10:]]))

now = int(time.time())


def words(vs, n=4):
    return ["%08x" % x for x in vs[:n]]


def tile_reps(vs):
    best = 0
    for i in range(0, len(vs) - 4):
        t = vs[i:i + 4]
        if not any(t):
            continue
        r = 1
        while i + 4 * (r + 1) <= len(vs) and vs[i + 4 * r:i + 4 * (r + 1)] == t:
            r += 1
        best = max(best, r)
    return best


for s, k in sizes[-4:]:
    seg = segs[k]
    print()
    print("=== segment %d (%d writes) ===" % (k, s))
    rows = []
    for st, m in seg.items():
        vs = [m[i] for i in sorted(m)]
        rows.append((len(vs), vs[0], vs, st))
    rows.sort(key=lambda r: -r[0])
    for cnt, v0, vs, st in rows[:14]:
        tag = ""
        if cnt == 36 and tile_reps(vs) >= 6:
            tag = "  <- #0 ?"
        if cnt == 5:
            tag = "  <- #9 ?"
        if cnt == 48:
            tag = "  <- BLOB ?"
        print("  count=%-4d first=%08x %s%s" % (cnt, v0, words(vs), tag))

print()
print("--- role-table scoring: any segment holding the full descriptor signature? ---")
for k, s in enumerate(segs):
    has = {
        "t36": any(len(v) == 36 for v in s.values()),
        "w8": any(len(v) == 8 for v in s.values()),
        "w5": any(len(v) == 5 for v in s.values()),
        "w4": any(len(v) == 4 for v in s.values()),
        "ones": sum(1 for v in s.values() if len(v) == 1),
        "claims": any(len(v) in (84, 90, 107, 113) for v in s.values()),
    }
    if has["t36"] and has["w8"] and (has["w5"] or has["claims"]):
        print("  seg=%-3d total=%-4d sig=%s" %
              (k, sum(len(v) for v in s.values()), sorted(len(v) for v in s.values())[:12]))