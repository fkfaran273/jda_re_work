"""Pass 9: (a) power-map/inverse families for F; (b) scan libsigner.so for a
stored table containing F's known values; (c) locate KB/IV2/K raw in the .so."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

def gmul_gen(a, b, poly):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a = ((a << 1) ^ poly) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return 0 if b == 0 else p  # note: loop count fixed 8

def gpow_gen(a, e, poly):
    r, base = 1, a
    while e:
        if e & 1: r = gmul_gen(r, base, poly)
        base = gmul_gen(base, base, poly)
        e >>= 1
    return r

W = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]
s4 = [(W[i-1], W[i] ^ W[i-8] ^ W[i-1]) for i in range(8, 60) if i % 8 == 4]
pairs = {}
for inp, out in s4:
    ib = inp.to_bytes(4, "big"); ob = out.to_bytes(4, "big")
    for j in range(4):
        pairs[ib[j]] = ob[j]
items = sorted(pairs.items())
n = len(items)

def check(tbl):
    b0 = items[0][1] ^ tbl[items[0][0]]
    return b0 if all(items[k][1] ^ tbl[items[k][0]] == b0 for k in range(1, n)) else None

# (a) bare inverse family over all odd polys: F(x) = inv_m(x^a) ^ b
hits = []
for poly in range(1, 256, 2):
    inv = [0]*256
    for v in range(1, 256):
        inv[v] = gpow_gen(v, 254, poly)
    for a in range(256):
        row = bytes(inv[x ^ a] for x in range(256))
        r = check(row)
        if r is not None:
            hits.append(("inv", poly, a, r))
print("bare-inverse hits:", hits)

# (b) power maps x^e over poly 0x1B and all polys: F(x) = (x^a)^e ^ b
hits2 = []
for poly in (0x1B,):
    for e in range(1, 256, 2):
        tbl = [gpow_gen(x, e, poly) for x in range(256)]
        for a in range(256):
            row = bytes(tbl[x ^ a] for x in range(256))
            r = check(row)
            if r is not None:
                hits2.append(("pow", hex(poly), e, a, r))
print("power-map hits (0x1B):", hits2)

# (c) scan the .so for a 256-byte table T with T[0x01]=0x21 T[0x10]=0x7e
#     T[0x14]=0x97 T[0x28]=0xd7
SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
data = open(SO, "rb").read()
print(f"\nlibsigner.so: {len(data)} bytes")
probes = [(0x01, 0x21), (0x10, 0x7e), (0x14, 0x97), (0x28, 0xd7),
          (0x9b, 0x10), (0xfb, 0x1f)]
anchor = bytes([0x21])  # will scan offsets manually with numpy-free loop
cand = []
off = 0
first_probe_off, first_probe_val = probes[0]
while True:
    i = data.find(bytes([first_probe_val]), off)
    if i < 0: break
    o = i - first_probe_off
    if o >= 0 and all(data[o + p] == v for p, v in probes):
        cand.append(o)
    off = i + 1
print(f"table candidates (all 6 probes match): {cand}")
for o in cand[:5]:
    tbl = data[o:o+256]
    mism = [(x, pairs[x], tbl[x]) for x in pairs if tbl[x] != pairs[x]]
    print(f"  offset 0x{o:x}: mismatches vs known F: {mism}")

# (d) locate KB, IV2, K raw in the file
for name, blob in (("KB", KB), ("IV2", IV2), ("K", K)):
    idx = []
    off = 0
    while True:
        i = data.find(blob, off)
        if i < 0: break
        idx.append(i); off = i + 1
    print(f"{name} raw occurrences: {[hex(x) for x in idx]}")
# half-block occurrences too
for name, blob in (("KB[0:16]", KB[:16]), ("KB[16:32]", KB[16:32]),
                   ("IV2[0:16]", IV2[:16]), ("K[0:16]", K[:16])):
    idx = []
    off = 0
    while True:
        i = data.find(blob, off)
        if i < 0: break
        idx.append(i); off = i + 1
    print(f"{name} occurrences: {[hex(x) for x in idx]}")
