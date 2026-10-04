"""app_fin5.py - analyze the FRESH appcap dump (2026-09-20, pid 6455).

Generalized from app_fin2.py: no hardcoded blob head or second.
 1. segment EMITs (pos-0 rule), find the signing segment (signature
    [1,1,1,1,1,4,5,8,36,90] i.e. 36w #0 + 90w #10 + 8w #4 + 5w #9 + 4w #8 + singles).
 2. find the 48w blob stream anywhere in the dump, invert its header -> true second.
 3. build descriptors from the segment, FinEx, expect BYTE-EXACT.
 4. emit a corpus row (app_signings2.json).
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
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
print("dump: nemit=%d nlenq=%d" % (d.get("nemit", -1), d.get("nlenq", -1)))


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
print("segments: %d" % len(segs))

# 1. locate the signing segment: contains a 36-slot stream with a repeated 4w tile
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

signing = None
for k, s in enumerate(segs):
    lens = sorted(len(m) for m in s.values())
    has36 = any(len(m) == 36 and tile_reps([m[i] for i in sorted(m)]) >= 6
                for m in s.values())
    has90 = any(len(m) in (84, 90, 97) for m in s.values())
    if has36 and has90:
        signing = (k, s)
        print("signing segment = %d  streams=%s" % (k, lens))
        break
if not signing:
    print("NO signing segment found"); sys.exit(1)
k0, seg = signing

def pick(cnt):
    return [[m[i] for i in sorted(m)] for m in seg.values() if len(m) == cnt]

z36 = max(pick(36), key=tile_reps)
z8 = pick(8)[0]
z5 = pick(5)
z4 = pick(4)
z1 = [v[0] for v in pick(1)]
z10 = pick(90) or pick(97) or pick(84)
print("#0 head: %s" % ["%08x" % x for x in z36[:4]])
print("#4 head: %s" % ["%08x" % x for x in z8[:4]])
print("#9 cands: %s" % [["%08x" % z[0] for z in z5]])
print("singles: %s" % ["%08x" % x for x in z1])
claims = b(z10[0])
print("#10: %d B, head=%s" % (len(claims), claims[:8].hex()))

# 2. find the blob stream + invert header for the true second
blob = None
for k, s in enumerate(segs):
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) == 48 and any(vs):
            # candidate: check if ANY small window second inverts words 0..3
            blob = vs
            print("blob candidate seg=%d head=%s" % (k, ["%08x" % x for x in vs[:4]]))
            break
    if blob:
        break

# invert header over a generous window around the claims' created_at
import re as _re
ca = _re.findall(rb"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", claims)
print("created_at fields:", ca[:2])
import datetime
sec_found = None
if blob and ca:
    y, mo, dd, hh, mi, ss = (int(x) for x in ca[0])
    base = int(datetime.datetime(y, mo, dd, hh, mi, ss, tzinfo=datetime.timezone.utc).timestamp())
    want = b(blob[:4])
    for delta in range(0, 7201):
        for s in ((base + delta, base - delta) if delta else (base,)):
            if make_header(s) == want:
                sec_found = s
                break
        if sec_found:
            break
print("inverted second:", sec_found)

# 3. descriptor assembly + FinEx
z10n = len(z10[0])
v = [x for x in z1 if x not in (0x168, 0x183, 0x19, 0, 0xC0, 0x90)]
d2 = max(v, key=lambda x: bin(x).count("1")) if v else 0
d7 = len(claims)
print("using #2=%08x #7=%08x" % (d2, d7))

def build(d9b):
    by = {0: (36, b(z36)), 9: (5, d9b), 8: (4, CONST8),
          4: (8, b(z8)), 2: (1, b([d2])), 7: (1, b([d7])),
          10: (z10n, b(z10[0])), 5: (1, b([0])), 6: (1, b([0])),
          1: (0, b""), 3: (0, b"")}
    return [(by[i][0], 0, by[i][1]) for i in ORDER]

if sec_found:
    ex = FinEx(sec_found, build(CONST9))
    stt = ex.run(max_steps=25_000_000)
    out = {}
    for (s_, n, vv) in ex.emit_trace:
        out[(s_, n)] = vv
    hdr = struct.unpack(">4I", make_header(sec_found))
    stream = None
    for (s_, n) in out:
        if tuple(out.get((s_, kk), 0) for kk in range(4)) == hdr:
            stream = s_
            break
    got = b"".join(struct.pack(">I", out.get((stream, kk), 0)) for kk in range(48)) if stream is not None else b""
    want = b(blob)
    diff = sum(1 for kk in range(48) if got[kk*4:kk*4+4] != want[kk*4:kk*4+4]) if got else 48
    print("FinEx: status=%s steps=%d %s" % (stt, ex.steps, "BYTE-EXACT" if got == want else "diff %d/48" % diff))

    if got == want:
        row = {"src": "app_dump.json (fresh signing, pid 6455)", "ev": "0",
               "second": sec_found, "blob": b(blob).hex(),
               "d0": b(z36).hex(), "d9": CONST9.hex(), "d8": CONST8.hex(),
               "d4": b(z8).hex(), "d2": "%08x" % d2, "d7": "%08x" % d7,
               "d10": claims.hex(), "d5": "00000000", "d6": "00000000"}
        json.dump([row], open(os.path.join(HERE, "app_signings2.json"), "w"), indent=1)
        print("saved app_signings2.json")
else:
    print("no second inverted; cannot verify")
