"""finex_click.py - FinEx battery on seg27 (fresh CLICK signing).

V1 base = app_fin4 recipe. Variants: #1/#3 non-empty (seg27 has 6 singles,
session seg0 had 5) with the leftover single values 0xc0 / 0x19.
#2 is KEPT at cd9d3a91 throughout (LENQ: it IS the read descriptor).
The 17w stream is NOT fed (output body section, verbatim at blob[40..47]).
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header
ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
SEC = 1789914579
CONST9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
CONST8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
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
blob = [vs for vs in byc[48] if b(vs[:4]) == make_header(SEC)][0]
claims97 = byc[97][0]
z36 = byc[36][0]
# byc is keyed by STREAM LENGTH: byc[8] = 8-word streams = #4, byc[4] = 4-word = #8
z4desc = byc[8][0]
z8desc = byc[4][0]
assert b(z8desc[:4]) == CONST8, "slot-8 source is not CONST8"
z9 = None
for vs in byc[5]:
    if b(vs[:5]) == CONST9:
        z9 = vs
        break
print("using #8=%s #4=%s" % (" ".join("%08x" % v for v in z8desc[:2]),
      " ".join("%08x" % v for v in z4desc[:2])), flush=True)
WANT = b(blob)
D2 = struct.pack(">I", 0xcd9d3a91)
HDR = struct.unpack(">4I", make_header(SEC))


def run(nm, d1=0, d3=0):
    by = {0: (36, b(z36)), 9: (5, b(z9)), 8: (4, b(z8desc)),
          4: (8, b(z4desc)), 2: (1, D2), 7: (1, struct.pack(">I", 387)),
          10: (97, b(claims97)),
          5: (1, struct.pack(">I", 0)), 6: (1, struct.pack(">I", 0)),
          1: ((1, struct.pack(">I", d1)) if d1 else (0, b"")),
          3: ((1, struct.pack(">I", d3)) if d3 else (0, b""))}
    ex = FinEx(SEC, [(by[i][0], 0, by[i][1]) for i in ORDER])
    st = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, v) in ex.emit_trace:
        out[(s_, n)] = v
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == HDR:
            stream = s_
            break
    got = (b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
           if stream is not None else b"")
    diff = (sum(1 for j in range(48) if got[j*4:j*4+4] != WANT[j*4:j*4+4])
            if got else 48)
    print("  %-16s status=%-10s steps=%-9d %s" %
          (nm, st, ex.steps, "BYTE-EXACT" if got == WANT else "diff %d/48" % diff),
          flush=True)
    return got == WANT


C0, X19 = 0xC0, 0x19
print("arms: #2=cd9d3a91 kept; 17w not fed", flush=True)
run("V1 base")
run("W1 #1=c0", d1=C0)
run("W2 #3=c0", d3=C0)
run("W3 #1=19", d1=X19)
run("W4 #3=19", d3=X19)
run("W5 #1=c0 #3=19", d1=C0, d3=X19)
run("W6 #1=19 #3=c0", d1=X19, d3=C0)
print("=== BATTERY DONE ===", flush=True)
