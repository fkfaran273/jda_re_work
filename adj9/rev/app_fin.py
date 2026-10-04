"""app_fin.py - THE decisive test with the app's OWN signing.

Reconstruct the descriptor set from the capture's best segment (role table, golden:
#10 claims | #0 36w tile | #4 8w | #9 5w | #8 4w | #2/#5/#6/#7 singles), find the
emitted blob (48-word stream, header must obey Random3(second)), then ask FinEx
whether it reproduces that blob BYTE-EXACTLY.

Specs from golden (whcap_hits7 + fin_descs): #9,#8,#5,#6 are CONSTANTS across all 10
real samples (CONST9/CONST8/0/0), so they are taken from there; the signing's own
streams supply #0,#4,#2,#7,#10.
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


EM = [(st, n, v) for st, n, v in d["emits"]]
segs = segment(EM)


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


print("=== candidates: segments with (36 & 8 & 5) streams ===")
pool = []
for k, s in enumerate(segs):
    have = sorted(len(v) for v in s.values())
    if 36 in have and 8 in have and 5 in have:
        pool.append(k)
        print("  seg=%-3d total=%-4d sig=%s" % (k, sum(len(v) for v in s.values()), have[:12]))

print()
print("=== blobs: 48-word streams whose head inverts under Random3 ===")
cands = []


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) < 48:
            continue
        head = b(vs[:4])
        # a valid header: try brute force +- a few hours (cheap at header-check speed)
        import time as _t
        ok = None
        for sec in range(int(_t.time()) - 14400, int(_t.time()) + 60):
            if make_header(sec) == head:
                ok = sec
                break
        if ok:
            cands.append((ok, k, st, vs))
            print("  second=%d seg=%d %s head=%s" %
                  (ok, k, str(st)[-8:], [("%08x" % x) for x in vs[:4]]))
print("blob candidates: %d" % len(cands))

print()
print("=== FinEx arms: descriptor sets reconstructed from own-signing segments ===")
FIN = {"done": 0, "exact": 0}


def run(nm, descs, target):
    import struct as _st
    ex = FinEx(target[0], descs)
    stt = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    hdr = _st.unpack(">4I", make_header(target[0]))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    got = b""
    if stream is not None:
        got = b"".join(_st.pack(">I", out.get((stream, k), 0)) for k in range(48))
    want = b(target[1][:48])
    diff = (sum(1 for k in range(48) if got[k * 4:k * 4 + 4] != want[k * 4:k * 4 + 4])
            if got else 48)
    ok = got == want
    FIN["done"] += 1
    FIN["exact"] += 1 if ok else 0
    print("  %-30s status=%-10s steps=%-9d %s" %
          (nm, stt, ex.steps, "BYTE-EXACT" if ok else "diff %d/48" % diff),
          flush=True)
    return ok


for sec, k, blob_st, blob_vs in cands[:4]:
    seg = segs[k]
    bylen = {}
    for st, m in seg.items():
        bylen.setdefault(len(m), []).append((st, [m[i] for i in sorted(m)]))
    z36 = max(bylen.get(36, []), key=lambda x: tile_reps(x[1]))[1] if bylen.get(36) else None
    z8 = bylen.get(8)[0][1] if bylen.get(8) else None
    cand10 = bylen.get(90) or bylen.get(84) or []
    z10 = max(cand10, key=lambda x: len(x[1]))[1] if cand10 else None
    singles = sorted([v[0] for _, v in bylen.get(1, [])],
                     key=lambda w: bin(w).count("1"), reverse=True)
    if not (z36 is not None and z8 is not None and z10 is not None and len(singles) >= 2):
        print("  seg=%d incomplete roles (have %s)" %
              (k, sorted(len(v) for v in seg.values())[:12]), flush=True)
        continue
    v = singles
    i7 = min(range(len(v)), key=lambda i: abs(v[i] - len(z10) * 4))
    i2 = max([i for i in range(len(v)) if i != i7],
             key=lambda i: bin(v[i]).count("1"))
    rest = [i for i in range(len(v)) if i not in (i7, i2)]
    by = {0: (36, b(z36)), 9: (5, CONST9), 8: (4, CONST8),
          4: (8, b(z8)), 2: (1, b([v[i2]])), 7: (1, b([v[i7]])),
          10: (len(z10), b(z10)),
          5: (1, b([v[rest[0]]]) if rest else b"\0\0\0\0"),
          6: (1, b([v[rest[1]]]) if len(rest) > 1 else b"\0\0\0\0"),
          1: (0, b""), 3: (0, b"")}
    run("seg=%d blob=%s" % (k, ("%08x" % blob_vs[0])), [(by[i][0], 0, by[i][1]) for i in ORDER], (sec, blob_vs))

print()
print("=== RESULT: %d/%d byte-exact ===" % (FIN["exact"], FIN["done"]))