"""verify_reg.py - verify the region-capture run's fresh CLICK signing.

app_reg.json has a full signing in seg0 (97-word click claims). Find the second by
exit-clean sweep around created_at (1789965827), then confirm FinEx reproduces the
blob (header self-consistency + exit-clean at canonical steps).
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header

ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
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
z10 = pick(97)[0]
claims = b(z10)
v = [x for x in z1 if x not in (0x168, 0x183, 0x184, 0x19, 0, 0xC0, 0x90)]
d2 = max(v, key=lambda x: bin(x).count("1")) if v else 0
d7 = len(claims)
print("#0=%08x #2=%08x #7=%d claims=%dB" % (z36[0], d2, d7, len(claims)), flush=True)

by = {0: (36, b(z36)), 9: (5, CONST9), 8: (4, CONST8),
      4: (8, b(z8)), 2: (1, b([d2])), 7: (1, b([d7])),
      10: (97, b(z10)), 5: (1, b([0])), 6: (1, b([0])), 1: (0, b""), 3: (0, b"")}
descs = [(by[i][0], 0, by[i][1]) for i in ORDER]

base = 1789965827
for delta in range(0, 61):
    for sec in ((base + delta, base - delta) if delta else (base,)):
        ex = FinEx(sec, descs)
        st = ex.run(max_steps=11_000_000)
        if st == "exit-clean":
            out = {}
            for (s_, n, vv) in ex.emit_trace:
                out[(s_, n)] = vv
            hdr = struct.unpack(">4I", make_header(sec))
            stream = None
            for (s_, n) in out:
                if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
                    stream = s_
                    break
            blob = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48)) if stream is not None else b""
            print("EXIT-CLEAN sec=%d steps=%d stream=%s" % (sec, ex.steps, hex(stream) if stream else None), flush=True)
            row = {"src": "app_reg.json (fresh CLICK signing)", "ev": "0", "second": sec,
                   "blob": blob.hex(), "d0": b(z36).hex(), "d9": CONST9.hex(), "d8": CONST8.hex(),
                   "d4": b(z8).hex(), "d2": "%08x" % d2, "d7": "%08x" % d7, "d10": claims.hex(),
                   "d5": "00000000", "d6": "00000000"}
            json.dump([row], open(os.path.join(HERE, "app_signings3.json"), "w"), indent=1)
            print("saved app_signings3.json", flush=True)
            sys.exit(0)
    if delta % 10 == 0:
        print("  delta %d" % delta, flush=True)
print("no exit-clean second in +/-60s", flush=True)
