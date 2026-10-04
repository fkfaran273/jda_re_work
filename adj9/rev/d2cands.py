"""d2cands.py - is the true #2 the 17-word stream? exact-dword battery.

Segment 27 of app_dump.json (fresh CLICK signing, second 1789914579):
  #2 cand (1w) = cd9d3a91 ; 17w stream head a6de2582 808c3d49 08734189 87339b88.
Test: exact membership of #2 / each 17w dword / their halves in
  {blob48, claims388, H-impossible, W0/tile, a[0..7]}. Plus: is any 17w dword
  == a[k] of the seg's own #4? is #2 a dword of the 17w stream?
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
SEC = 1789914579


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
claims = byc[97][0]
z4 = byc[8][0]
w17 = byc[17][0]
D2C = 0xcd9d3a91
bb, cb = b(blob), b(claims)
print("17w =", " ".join("%08x" % v for v in w17))
print("d2cand = %08x" % D2C)
print("d2cand in blob(BE/LE):", D2C in [int.from_bytes(bb[j:j+4], "big") for j in range(0, 192, 4)],
      D2C in [int.from_bytes(bb[j:j+4], "little") for j in range(0, 192, 4)])
print("d2cand in claims(BE/LE):", D2C in [int.from_bytes(cb[j:j+4], "big") for j in range(0, 385, 4)],
      D2C in [int.from_bytes(cb[j:j+4], "little") for j in range(0, 385, 4)])
print("d2cand in 17w:", D2C in w17)
print("17w dwords in blob:", [("%08x" % v) for v in w17
      if v in [int.from_bytes(bb[j:j+4], "big") for j in range(0, 192, 4)]] or "none")
print("17w dwords in claims:", [("%08x" % v) for v in w17
      if v in [int.from_bytes(cb[j:j+4], "big") for j in range(0, 385, 4)]] or "none")
print("17w dwords in #4:", [("%08x" % v) for v in w17 if v in z4] or "none")
hw = [(v >> 16) & 0xFFFF for v in w17] + [v & 0xFFFF for v in w17]
print("17w halves shared with a[6] halves:",
      [("%04x" % v) for v in hw if v in (((z4[6] >> 16) & 0xFFFF), z4[6] & 0xFFFF)] or "none")
t = None
raw0 = None
for vs in byc[36]:
    raw0 = vs
    break
T = raw0[1:5]
X = (T[0] ^ T[1]) & 0xFFFFFFFF
R = None
K13 = (T[3] ^ T[1]) & 0xFFFFFFFF
R = (K13 >> 16) & 0xFFFF
print("tile R=%04x X=%08x; 17w dwords == R-halves:" % (R, X),
      [("%08x" % v) for v in w17 if ((v >> 16) & 0xFFFF) == R or (v & 0xFFFF) == R] or "none")
