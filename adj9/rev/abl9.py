"""abl9.py - is #9 (or #8) actually CONSUMED by the VM?

app_fin2 reproduced the app signing BYTE-EXACT from its descriptor set.  Replace
#9 with zeros (then #8) and re-run: if the blob still reproduces exactly, that
descriptor is decorative inside the VM (its words are never read) -- which is the
same conclusion the slice-119 golden-trace analysis reached by a different route
(0/5 #9 words and 0/4-of-interest present as EMIT output).
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
SEC = 1789903463
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
GOLD = json.load(open(os.path.join(os.path.dirname(HERE), "device", "whcap_hits7.json")),
                 encoding="utf-8") if False else None


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
seg = segs[0]
D = {}
for st, m in seg.items():
    D[len(m)] = [m[i] for i in sorted(m)]


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
Z5 = b"\0" * 20
Z4 = b"\0" * 16
D = {}
for st, m in seg.items():
    D.setdefault(len(m), []).append([m[i] for i in sorted(m)])
print("seg0 by count:", sorted((c, ["%08x" % v[0] for v in vs]) for c, vs in D.items()))
v1 = sorted([v[0] for v in D[1]], key=lambda w: bin(w).count("1"), reverse=True)
i7 = min(range(len(v1)), key=lambda i: abs(v1[i] - 360))
i2 = max([i for i in range(len(v1)) if i != i7], key=lambda i: bin(v1[i]).count("1"))
z36 = D[36][0] if len(D.get(36, [])) == 1 else None
z8 = D[8][0] if len(D.get(8, [])) == 1 else None
z10 = D[90][0] if D.get(90) else D[84][0]
if z36 is None or z8 is None or not D.get(90) and not D.get(84):
    print("ambiguous/missing roles; D keys:", sorted(D))

# target blob: the 48-word stream in seg96
BLOB = None
for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) >= 48 and vs[:4] == [0x39D1D36D, 0x1F9E5768, 0x354A181A, 0x73FBF251]:
            BLOB = vs[:48]
            break
    if BLOB:
        break


def run(nm, d9b, d8b):
    by = {0: (36, b(z36)), 9: (5, d9b), 8: (4, d8b),
          4: (8, b(z8)), 2: (1, b([v1[i2]])), 7: (1, b([v1[i7]])),
          10: (len(z10), b(z10)), 5: (1, b([0])), 6: (1, b([0])),
          1: (0, b""), 3: (0, b"")}
    ex = FinEx(SEC, [(by[i][0], 0, by[i][1]) for i in ORDER])
    stt = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, val) in ex.emit_trace:
        out[(s_, n)] = val
    hdr = struct.unpack(">4I", make_header(SEC))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    got = b""
    if stream is not None:
        got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
    want = b(BLOB)
    ok = got == want
    print("  %-22s status=%-10s steps=%-9d %s" %
          (nm, stt, ex.steps, "BYTE-EXACT" if ok else "diff %d/48" %
           (sum(1 for k in range(48) if got[k * 4:k * 4 + 4] != want[k * 4:k * 4 + 4])
            if got else 48)),
          flush=True)
    return ok


print("baseline (#9=CONST9):")
ok0 = run("baseline", CONST9, CONST8)
print("#9=zeros / #8=zeros ablations:")
ok1 = run("#9=zeros", Z5, CONST8)
ok2 = run("#8=zeros", CONST9, Z4)
print("RESULT baseline=%s #9=zeros-exact=%s #8=zeros-exact=%s" % (ok0, ok1, ok2))