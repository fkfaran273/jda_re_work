"""app_pair.py - is app_dump's segment 0 fresh or a replay of the golden?

Compare value-by-value, then take the pairing that matters: descriptors from the
app's own signing + the emitted blob (seg96, seconded) -> FinEx BYTE-EXACT?
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.stdout.reconfigure(line_buffering=True)

gold = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
app = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


def ordered(seg):
    out = {}
    for st, m in seg.items():
        out[st] = [m[i] for i in sorted(m)]
    return out


gs = segment([(int(r["sink"], 16), int(r["pos"], 16), int(r["val"], 16))
              for r in gold if isinstance(r, dict) and r.get("tag") == "emit"])
asg = segment([(st, n, v) for st, n, v in app["emits"]])

print("golden segments: %d  app segments: %d" % (len(gs), len(asg)))
g0 = ordered(gs[0])
a0 = ordered(asg[0])
gb = sorted((len(v), v) for k, v in g0.items())
ab = sorted((len(v), v) for k, v in a0.items())
print("golden seg0 :", [(c, ["%08x" % x for x in v[:3]]) for c, v in gb])
print("app seg0    :", [(c, ["%08x" % x for x in v[:3]]) for c, v in ab])

same = True
for (gc, gv), (ac, av) in zip(gb, ab):
    if gc != ac or gv != av:
        same = False
        break
print()
print("app seg0 == golden seg0 :", same)

# --- the blob candidate from app_seg: second=1789903463 seg=96 ----------------
target = None
for k, s in enumerate(asg):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) >= 48 and vs[:4] == [0x39D1D36D, 0x1F9E5768, 0x354A181A, 0x73FBF251]:
            target = (1789903463, vs[:48])
            print("blob found in app seg %d (%s)" % (k, str(st)[-8:]))
            break
    if target:
        break
print("blob head BE:", ["%08x" % x for x in (target[1][:4] if target else [])])
json.dump({"seg0_equal_gold": same,
           "gold_first": {c: [("%08x" % x) for x in v[:2]] for c, v in gb},
           "app_first": {c: [("%08x" % x) for x in v[:2]] for c, v in ab}},
          open(os.path.join(HERE, "app_pair.json"), "w"))
print("saved app_pair.json")