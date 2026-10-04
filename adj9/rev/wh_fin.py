"""wh_fin.py - corrected byte order + THE decisive test.

LENQ/EMIT values are the VM's *big-endian* dwords (LDR then REV).  So descriptor
bytes = struct.pack(">I", v).  Earlier arms compared little-endian and therefore
searched for the wrong words -- that is why fin118 failed.

Here: take the captured stream plane of a labelled mint, identify each descriptor
(#0 36w with a repeated 16-byte tile, #10 = claims length, #4 8w, #8 4w,
#2/#5/#6/#7 = single words), rebuild the descriptor set, and ask FinEx whether it
reproduces the blob byte-exactly.
"""
import base64
import calendar
import datetime
import json
import os
import re
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
d = json.load(open(os.path.join(HERE, "wh_out.json"), encoding="utf-8"))
blob = base64.b64decode(d["blobB64"])
print("blob:", blob.hex())

# ---- second from the map's own created_at (claims carry it) ----------------
pairs = dict((k, v) for k, v in d["mapPairs"])
print("created_at:", pairs.get("created_at"), " sent_at:", pairs.get("sent_at"))


def wall_second(ca):
    dt = datetime.datetime.strptime(ca[:19], "%Y-%m-%dT%H:%M:%S")
    off = ca[-5:]
    sgn = 1 if off[0] == "+" else -1
    return calendar.timegm(dt.timetuple()) - sgn * (int(off[1:3]) * 3600 + int(off[3:5]) * 60)


sec = None
base = wall_second(pairs["created_at"])
for cand in (base, base + 1, base - 1, base + 2, base - 2, base + 3, base + 4):
    if make_header(cand) == blob[:16]:
        sec = cand
        break
if sec is None:
    # the map carries a STALE created_at, so the signing second is only bounded by
    # "before now" -- search the whole plausible window (unique match expected)
    print("created_at window missed; wide search (this takes ~1 min)", flush=True)
    for s in range(1789800000, 1789902000):
        if make_header(s) == blob[:16]:
            sec = s
            break
print("second:", sec, "header law:", make_header(sec) == blob[:16] if sec else None)
assert sec, "header law: no second found"


def plane(rows):
    S = {}
    for st, n, v in rows:
        S.setdefault(st, {})[n] = v
    return dict((st, [S[st][k] for k in sorted(S[st])]) for st in S)


A = plane(d["emits"])
B = plane(d["lenq"])
for nm, pl in (("EMIT", A), ("LENQ", B)):
    bylen = {}
    for st, vs in pl.items():
        bylen.setdefault(len(vs), []).append((st, vs))
    print("%s streams:" % nm,
          dict((k, [("%s" % st)[-6:] for st, _ in v]) for k, v in sorted(bylen.items())))

CLAIMS_LEN = 336


def popcount(x):
    return bin(x).count("1")


def pick(pl, srcname):
    bylen = {}
    for st, vs in pl.items():
        bylen.setdefault(len(vs), []).append((st, vs))
    out = {}
    # #0: 36 words with a repeated 16-byte tile
    cand0 = []
    for st, vs in bylen.get(36, []):
        best = 0
        for i in range(0, len(vs) - 4):
            t = vs[i:i + 4]
            if not any(t):
                continue
            r = 1
            while i + 4 * (r + 1) <= len(vs) and vs[i + 4 * r:i + 4 * (r + 1)] == t:
                r += 1
            best = max(best, r)
        cand0.append((best, st, vs))
    cand0.sort(key=lambda x: -x[0])
    print("  [%s] 36-word streams by tile reps: %s" %
          (srcname, [(r, str(st)[-6:]) for r, st, _ in cand0]))
    out["d0"] = cand0[0][2]
    out["d0_st"] = cand0[0][1]
    out["d10"] = bylen[84][0][1]
    out["d4"] = bylen[8][0][1]
    out["d8"] = bylen[4][0][1]
    singles = sorted(bylen[1], key=lambda x: -x[1][0])
    out["singles"] = singles
    print("  [%s] singles: %s" % (srcname, [(str(st)[-6:], "%08x" % vs[0]) for st, vs in singles]))
    return out


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


def run(name, p, d5_6_swap=False):
    s = p["singles"]
    v = [x[1][0] for x in s]
    # #7 = the length-like word (claims byte length)
    i7 = min(range(4), key=lambda i: abs(v[i] - CLAIMS_LEN))
    i2 = max([i for i in range(4) if i != i7], key=lambda i: popcount(v[i]))
    rest = [i for i in range(4) if i not in (i7, i2)]
    i5, i6 = (rest[1], rest[0]) if d5_6_swap else (rest[0], rest[1])
    by = {0: (36, b(p["d0"])), 9: (5, CONST9), 8: (4, CONST8),
          4: (8, b(p["d4"])), 2: (1, b(s[i2][1])), 7: (1, b(s[i7][1])),
          10: (84, b(p["d10"])), 5: (1, b(s[i5][1])), 6: (1, b(s[i6][1])),
          1: (0, b""), 3: (0, b"")}
    print("  [%s] map: #7=%08x #2=%08x #5=%08x #6=%08x" %
          (name, v[i7], v[i2], v[i5], v[i6]), flush=True)
    ex = FinEx(sec, [(by[i][0], 0, by[i][1]) for i in ORDER])
    st = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, val) in ex.emit_trace:
        out[(s_, n)] = val
    hdr = struct.unpack(">4I", make_header(sec))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
            stream = s_
            break
    got = b""
    if stream is not None:
        got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
    diff = (sum(1 for k in range(48) if got[k * 4:k * 4 + 4] != blob[k * 4:k * 4 + 4])
            if got else 48)
    print("  [%s] status=%-8s steps=%-9d %s" %
          (name, st, ex.steps, "BYTE-EXACT" if got == blob else "diff %d/48" % diff),
          flush=True)
    return got == blob


print()
print("=== descriptor sets from the captured plane ===")
ok = 0
for nm, pl in (("EMIT", A), ("LENQ", B)):
    p = pick(pl, nm)
    for sw in (False, True):
        if run("%s #5/#6 swap=%s" % (nm, sw), p, sw):
            ok += 1
print()
print("=== RESULT: %d byte-exact arm(s) ===" % ok)