"""sec_sweep5.py - find the second that makes the fresh descriptor set exit-clean.

For each candidate second around created_at (1789929323), run FinEx and record
status + steps. The true signing second is the one that exits clean (the VM only
terminates when the OP_RAND draws line up, which is second-dependent - slice 136).
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx

ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
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


def tile_reps(vs):
    best = 0
    for i in range(0, len(vs) - 8):
        t = vs[i:i + 4]
        if not any(t):
            continue
        r = 1
        while i + 4 * (r + 1) <= len(vs) and vs[i + 4 * r:i + 4 * (r + 1)] == t:
            r += 1
        best = max(best, r)
    return best


segs = segment([(st, n, v) for st, n, v in d["emits"]])
seg = segs[0]

def pick(cnt):
    return [[m[i] for i in sorted(m)] for m in seg.values() if len(m) == cnt]

z36 = max(pick(36), key=tile_reps)
z8 = pick(8)[0]
z1 = [v[0] for v in pick(1)]
z10 = pick(90)[0]
claims = b(z10)
v = [x for x in z1 if x not in (0x168, 0x183, 0x19, 0, 0xC0, 0x90)]
d2 = max(v, key=lambda x: bin(x).count("1")) if v else 0
d7 = len(claims)
by = {0: (36, b(z36)), 9: (5, CONST9), 8: (4, CONST8),
      4: (8, b(z8)), 2: (1, b([d2])), 7: (1, b([d7])),
      10: (90, b(z10)), 5: (1, b([0])), 6: (1, b([0])), 1: (0, b""), 3: (0, b"")}
descs = [(by[i][0], 0, by[i][1]) for i in ORDER]

base = 1789929323
print("descs ready; sweeping", flush=True)
results = []
for delta in range(0, 121):
    for sec in ((base + delta, base - delta) if delta else (base,)):
        ex = FinEx(sec, descs)
        st = ex.run(max_steps=11_000_000)
        results.append((sec, st, ex.steps))
        if st == "exit-clean":
            print("EXIT-CLEAN sec=%d steps=%d" % (sec, ex.steps), flush=True)
            json.dump({"second": sec}, open(os.path.join(HERE, "sec5_found.json"), "w"))
            sys.exit(0)
    if delta % 10 == 0:
        print("  delta %d done (all step-cap so far)" % delta, flush=True)
print("no exit-clean second in +/-120s", flush=True)
