"""seg27_probe.py - lean decode of the fresh capture's segment 27.

1. segment the plane (pos-0 rule), show segment 27's roles;
2. extract created_at from the 97-word claims -> ws;
3. test make_header(ws-2..ws+3) against every 48-word stream's head;
4. report second + blob head, no VM run.
"""
import json, os, re, struct, sys, calendar, datetime
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


segs = segment([(st, n, v) for st, n, v in d["emits"]])
print("segments:", len(segs))


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


for k, seg in enumerate(segs):
    byc = {}
    for st, m in seg.items():
        byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])
    if 48 in byc and 36 in byc and 8 in byc and 5 in byc:
        print("--- seg %d sizes %s ---" % (k, sorted(len(v) for v in seg.values())))
        for cnt, lst in sorted(byc.items()):
            for vs in lst[:3]:
                print("  n=%-3d first=%s" % (cnt, " ".join("%08x" % v for v in vs[:4])))
        cands = byc.get(97, []) + byc.get(96, [])
        if cands:
            cl = b(cands[0]).decode("latin1", "replace")
            m = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d{3}Z([+-]\d{4})", cl)
            if m:
                dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
                off = m.group(2)
                sgn = 1 if off[0] == "+" else -1
                ws = calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)
                print("  claims[0]=%dB created_at=%s ws=%d" % (len(b(cands[0])), m.group(0), ws))
                hdrs = {s: make_header(s) for s in range(ws - 3, ws + 4)}
                for vs in byc[48]:
                    for s, h in hdrs.items():
                        if b(vs[:4]) == h:
                            print("  ** blob48 head matches second=%d (%s)" % (s, " ".join("%08x" % v for v in vs[:4])))
