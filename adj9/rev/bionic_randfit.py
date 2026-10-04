"""bionic_randfit.py - fit region words to time-seeded bionic streams.

Model: srand(time(NULL)) once per process (0x12cbbc time + 0x12cbc0 srand),
then rand() draws inside the VM (0x12a2fc/0x12a31c). Bionic TYPE_3 additive
feedback (same recurrence as header_gen.Random3): seed the stream with the
signing second S (and S-1 for claims-vs-header skew, masked variants) and
report each region word's draw index (N<=4000). Rows: 6 clean + app.
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import M31
PH = {r["i"]: r for r in json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))}
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
def bionic(seed, n=4000):
    r = [0]*34
    st = seed & 0xFFFFFFFF
    if st == 0: st = 1
    r[0] = st if st < 2**31 else st - 2**32
    prev = r[0]
    for i in range(1, 31):
        hi = prev//127773 if prev >= 0 else -((-prev)//127773)
        lo = prev - hi*127773
        w = 16807*lo - 2836*hi
        if w < 0: w += M31
        r[i] = prev = w
    f, b = 3, 0
    out = []
    for _ in range(n):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < 2**31 else v - 2**32
        out.append(v >> 1)
        f = (f+1) % 31; b = (b+1) % 31
    return out
def be(h, n):
    raw = bytes.fromhex(h)
    return [int.from_bytes(raw[j:j+4], "big") for j in range(0, 4*n, 4)]
ROWS = []
for i in (0, 1, 4, 5, 6, 7):
    r = PH[i]
    ROWS.append((i, r["second"], r["d0"], r["d2"], r["d4"]))
ROWS.append(("app", A["second"], A["d0"], A["d2"], A["d4"]))
for i, sec, d0, d2, d4 in ROWS:
    w = be(d0, 5); W0, tile = w[0], w[1:5]
    a = be(d4, 8); d2v = int(d2, 16)
    tg = {"W0": W0, "T0": tile[0], "T1": tile[1], "T2": tile[2], "T3": tile[3],
          "d2": d2v, "a7": a[7], "a6": a[6]}
    tset = set(tg.values())
    best = []
    for cand in (sec, sec-1, sec & 0x7FFFFFFF, (sec-1) & 0x7FFFFFFF):
        seq = bionic(cand)
        pos = {}
        for k, v in enumerate(seq):
            if v in tset and v not in pos:
                pos[v] = k
        hit = sorted(((nm, pos[v]) for nm, v in tg.items() if v in pos), key=lambda x: x[1])
        if hit:
            best.append((cand, hit))
    print("[%-3s] sec=%d %s" % (i, sec, best if best else "none"))
