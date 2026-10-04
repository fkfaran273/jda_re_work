"""app_row.py - save the app's own fresh signing as a labelled corpus row.

all_signings.json holds 10 rows from OLD captures; this appends the freshly captured
app signing (claims dated 2026-09-20T16:50, second 1789903463, blob seen in seg96, both
FinEx arms BYTE-EXACT) so the fitting set no longer rests on a single sample family.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.stdout.reconfigure(line_buffering=True)

CONST9 = "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"
CONST8 = "bffffffffffffd1f0007000000000000"


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


d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
seg = segment([(st, n, v) for st, n, v in d["emits"]])[0]
byc = {}
for st, m in seg.items():
    byc.setdefault(len(m), []).append([m[i] for i in sorted(m)])

z36 = max(byc[36], key=lambda vs: sum(1 for i in range(len(vs) - 4)
                                     if vs[i:i + 4] == vs[1:5] and any(vs[i:i + 4])))
# pick the tile one explicitly
def reps(vs):
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


z36 = max(byc[36], key=reps)
z8 = byc[8][0]
z10 = byc[90][0] if byc.get(90) else byc[84][0]
sing = sorted([v[0] for v in byc.get(1, [])], key=lambda w: bin(w).count("1"), reverse=True)
d2 = max([s for s in sing if s not in (0x168, 0x19, 0)], key=lambda w: bin(w).count("1"))
claims = b(z10)
blob48 = None
for k2, s2 in enumerate(segment([(st, n, v) for st, n, v in d["emits"]])):
    for st, m in s2.items():
        vs = [m[i] for i in sorted(m)]
        if len(vs) >= 48 and vs[:4] == [0x39D1D36D, 0x1F9E5768, 0x354A181A, 0x73FBF251]:
            blob48 = vs[:48]
            break
    if blob48:
        break
row = {"src": "app_dump.json (app's own fresh signing)",
       "ev": "0",
       "second": 1789903463,
       "blob": b(blob48).hex() if blob48 else "",
       "d0": b(z36).hex(), "d9": CONST9, "d8": CONST8, "d4": b(z8).hex(),
       "d2": "%08x" % d2, "d7": "%08x" % 360, "d10": claims.hex(),
       "d5": "00000000", "d6": "00000000",
       "claims_tail": claims[-60:].decode("latin1", "replace"),
       "claims_iso": [x.decode("ascii") for x in __import__("re").findall(
           rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\+\d{4}", claims)]}

dz36 = [int.from_bytes(bytes.fromhex(row["d0"])[i:i + 4], "big") for i in range(0, 20, 4)]
print("d0 W0=%08x tile=%s" %
      (dz36[0], ["%08x" % x for x in dz36[1:5]]))
print("d2=%s d7=%s claims=%dB iso=%s" % (row["d2"], row["d7"], len(claims), row["claims_iso"]))

out = os.path.join(HERE, "app_signings.json")
json.dump([row], open(out, "w"), indent=1)
print("saved", out)