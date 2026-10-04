"""app_fin2.py - THE test for the 56-byte region (Path A data in hand).

App's own signing (app_dump.json): seg0 holds the complete descriptor set written by
the builder itself -- #0 (36w, fresh tile), #4 (8w), #9 (5w), #8 (4w), singles,
#10 (90w claims).  The blob it produced is seg96's 48-word stream (second 1789903463).

Feed THOSE descriptors into FinEx and check BYTE-EXACTNESS:
  exact  -> the region plane is sufficient; only its derivation remains.
  no     -> the reused (especially #9 = CONST9 from another signing) or misassigned
            slot is wrong.
"""
import base64
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
print("segments: %d" % len(segs))
seg = segs[0]
print("seg0 streams: %s" % sorted(len(v) for v in seg.values()))


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def pick(cnt, first=None):
    out = []
    for st, m in seg.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) == cnt and (first is None or vs[0] == first):
            out.append(vs)
    return out


z36 = pick(36)[0]
z8 = pick(8)[0]
z5 = pick(5)
z4 = pick(4)
z1 = [v[0] for v in pick(1)]
z10 = pick(90)
print("#0 : %s..." % ["%08x" % x for x in z36[:4]])
print("#4 : %s..." % ["%08x" % x for x in z8[:4]])
print("#9 : %d candidates %s" % (len(z5), ["%08x" % z[0] for z in z5][:4]))
print("#8 : %d candidates" % len(z4))
print("1s : %s" % ["%08x" % x for x in z1])
print("#10: %d candidates, first=%s" % (len(z10), "%08x" % z10[0][0] if z10 else "-"))

# singles: #7 = 0x168 (=360, claims length), #2 = the random-looking one
sec = 1789903463
blob = None
for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) >= 48 and vs[:4] == [0x39D1D36D, 0x1F9E5768, 0x354A181A, 0x73FBF251]:
            blob = vs[:48]
            print("blob seg=%d len=%d" % (k, len(vs)))
            break
    if blob:
        break
print("blob head:", ["%08x" % x for x in blob[:4]])
print("header law:", make_header(sec) == b(blob[:4]))

FIN = {"done": 0, "exact": 0}


def run(nm, descs):
    ex = FinEx(sec, descs)
    stt = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = struct.unpack(">4I", make_header(sec))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    got = b""
    if stream is not None:
        got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
    want = b(blob)
    diff = (sum(1 for k in range(48) if got[k * 4:k * 4 + 4] != want[k * 4:k * 4 + 4])
            if got else 48)
    ok = got == want
    FIN["done"] += 1
    FIN["exact"] += 1 if ok else 0
    print("  %-34s status=%-10s steps=%-9d %s" %
          (nm, stt, ex.steps, "BYTE-EXACT" if ok else "diff %d/48" % diff),
          flush=True)
    return ok


v = [x for x in z1 if x not in (0x168, 0x19, 0)]
d2 = max(v, key=lambda x: bin(x).count("1")) if v else 0
d7 = 0x168
print("using #2=%08x #7=%08x" % (d2, d7))


def build(d9b):
    by = {0: (36, b(z36)), 9: (5, d9b), 8: (4, CONST8),
          4: (8, b(z8)), 2: (1, b([d2])), 7: (1, b([d7])),
          10: (90, b(z10[0])), 5: (1, b([0])), 6: (1, b([0])),
          1: (0, b""), 3: (0, b"")}
    return [(by[i][0], 0, by[i][1]) for i in ORDER]


run("#9=CONST9(golden)", build(CONST9))
for z in z5:
    run("#9=captured(%08x)" % z[0], build(b(z)))

print()
print("=== RESULT: %d/%d byte-exact ===" % (FIN["exact"], FIN["done"]))