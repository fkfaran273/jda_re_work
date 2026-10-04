"""fit_unitsweep.py - sensitive positional sweep.

The wire builder assembles the region in 16-bit units (the whitener is
`ldrh/eor/strh`), so the region is very unlikely to be a *linear* slice of a
keystream.  This sweeps every (output position, region position) pair at both
16-bit and 32-bit granularity and reports the pairs that agree across ALL
sampled V values.  A chance agreement at 16-bit granularity is ~0.35 per row,
so a pair agreeing on >=10/12 rows is a real signal, not noise.

Also runs a positive control (region vs itself) to prove the scorer works.
"""
import struct
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fit_table as F
import fit_families as FF

REGION_U = None
REGION_W = None


def prep(rows):
    """region unit/word arrays; d0||d2||d4"""
    global REGION_U, REGION_W
    us, ws = [], []
    for r in rows:
        reg = r["d0"] + r["d2"] + r["d4"]
        us.append([(reg[i] << 8) | reg[i + 1] for i in range(0, len(reg), 2)])
        ws.append([reg[i] << 24 | reg[i + 1] << 16 | reg[i + 2] << 8 | reg[i + 3]
                   for i in range(0, len(reg), 4)])
    return us, ws


def sweep(name, gen, rows, us, ws, nout=256):
    out_us, out_ws = [], []
    for r in rows:
        o = gen(r["V"], r["pid"], r["tid"])
        if o is None or len(o) < 8:
            return
        out_us.append([(o[i] << 8) | o[i + 1] for i in range(0, min(len(o), nout * 2), 2)])
        out_ws.append([o[i] << 24 | o[i + 1] << 16 | o[i + 2] << 8 | o[i + 3]
                       for i in range(0, min(len(o), nout * 4), 4)])
    n = len(rows)
    hits16 = []
    for j in range(len(out_us[0])):
        col = [out_us[i][j] for i in range(n)]
        for k in range(len(us[0])):
            c = sum(1 for i in range(n) if col[i] == us[i][k])
            if c >= max(3, n - 2):
                hits16.append((c, j, k))
    hits32 = []
    for j in range(len(out_ws[0])):
        col = [out_ws[i][j] for i in range(n)]
        for k in range(len(ws[0])):
            c = sum(1 for i in range(n) if col[i] == ws[i][k])
            if c >= max(2, n - 1):
                hits32.append((c, j, k))
    if hits16 or hits32:
        print("  %-40s 16b:%s  32b:%s" %
              (name, sorted(hits16, reverse=True)[:4], sorted(hits32, reverse=True)[:4]))
    return hits16, hits32


def main():
    rows = F.dedup(F.load_all())
    rows = [r for r in rows if r["era"] == 2]
    # collapse to distinct (V,pid,tid) keeping first
    seen, uniq = set(), []
    for r in rows:
        k = (r["V"], r["pid"], r["tid"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    rows = uniq
    us, ws = prep(rows)
    print("sweeping %d distinct (V,pid,tid) era-2 rows" % len(rows))
    # positive control
    ctrl = sweep("POSITIVE CONTROL region-vs-region",
                 lambda V, p, t: (REGION_CACHE["d0"] + REGION_CACHE["d2"] + REGION_CACHE["d4"]),
                 rows, us, ws)
    print("control found hits (expected):", bool(ctrl and (ctrl[0] or ctrl[1])))

    gens = []
    for sn, _ in FF.seeds(0, 1, 2):
        gens.append(("splitmix64[%s]" % sn,
                     lambda V, p, t, sn=sn: FF.splitmix64_stream(dict(FF.seeds(V, p, t))[sn], 1024)))
        gens.append(("xorshift64*[%s]" % sn,
                     lambda V, p, t, sn=sn: FF.xorshift64star(dict(FF.seeds(V, p, t))[sn], 1024)))
        gens.append(("xoshiro256ss[%s]" % sn,
                     lambda V, p, t, sn=sn: FF.xoshiro256ss(dict(FF.seeds(V, p, t))[sn], 1024)))
        gens.append(("pcg32[%s]" % sn,
                     lambda V, p, t, sn=sn: FF.pcg32_stream(dict(FF.seeds(V, p, t))[sn], 1024)))
        gens.append(("sha256[%s]" % sn,
                     lambda V, p, t, sn=sn: FF._sha(struct.pack(">I", dict(FF.seeds(V, p, t))[sn] & 0xFFFFFFFF), 1024)))
    keymakers = {
        "Vbe4": lambda V, p, t: struct.pack(">I", V & 0xFFFFFFFF),
        "Vle4": lambda V, p, t: struct.pack("<I", V & 0xFFFFFFFF),
        "Vp^t": lambda V, p, t: struct.pack(">I", (V ^ p ^ t) & 0xFFFFFFFF),
        "Vbe4p|t": lambda V, p, t: struct.pack(">III", V & 0xFFFFFFFF, p & 0xFFFFFFFF, t & 0xFFFFFFFF),
    }
    for kn, km in keymakers.items():
        gens.append(("rc4[%s]" % kn, lambda V, p, t, km=km: FF.rc4_stream(km(V, p, t), 1024)))
    gens.append(("sha256(Vbe4)", lambda V, p, t: FF._sha(struct.pack(">I", V & 0xFFFFFFFF), 1024)))
    gens.append(("sha1(Vbe4)", lambda V, p, t: FF._sha1(struct.pack(">I", V & 0xFFFFFFFF), 1024)))
    gens.append(("md5(Vbe4)", lambda V, p, t: FF._md5(struct.pack(">I", V & 0xFFFFFFFF), 1024)))
    gens.append(("sha256(Vbe4|p|t)", lambda V, p, t: FF._sha(FF.venc(V, p, t), 1024)))
    for mode in ("hi16", "sh1", "raw", "le"):
        gens.append(("bionic_random3[V,%s]" % mode,
                     lambda V, p, t, mode=mode: dict(
                         (m, o) for m, o in FF.lcg_rand3(V, 256)).get(mode)))
        gens.append(("bionic_random3[V^p^t,%s]" % mode,
                     lambda V, p, t, mode=mode: dict(
                         (m, o) for m, o in FF.lcg_rand3(V ^ p ^ t, 256)).get(mode)))
    gens.append(("aesctr[V^p^tpad]",
                 lambda V, p, t: FF._keystream_aes_ctr(
                     struct.pack(">I", (V ^ p ^ t) & 0xFFFFFFFF) + b"\0" * 12, b"\0" * 16, 1024)))
    gens.append(("chacha[V^p^t_x4]",
                 lambda V, p, t: FF._keystream_chacha(
                     struct.pack(">IIII", (V ^ p ^ t) & 0xFFFFFFFF, (V ^ p ^ t) & 0xFFFFFFFF,
                                 p & 0xFFFFFFFF, t & 0xFFFFFFFF), b"\0" * 16, 1024)))
    for name, g in gens:
        sweep(name, g, rows, us, ws)
    print("done.")


REGION_CACHE = {}

if __name__ == "__main__":
    # fill control cache with the first row's region
    _rows = F.dedup(F.load_all())
    _r = [x for x in _rows if x["era"] == 2][0]
    REGION_CACHE.update(d0=_r["d0"], d2=_r["d2"], d4=_r["d4"])
    main()
