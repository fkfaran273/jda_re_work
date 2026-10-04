"""fit_16bit.py - 16-bit PRG family sweep.

The wire-builder whitener works in 16-bit units (`ldrh w4,[x19]; eor w4,w4,w2;
strh w4,[x11]`), so the keystream that feeds the region may be a 16-bit (or
32-bit-with-16-bit-halves) generator.  This sweeps LCG16 / xorshift16 / LFSR16
/ 32-bit LCG families against every (output position, region 16-bit position)
pair, requiring agreement on >= N-2 of the sampled V rows.
"""
import struct
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fit_table as F

M16 = 0xFFFF
M32 = 0xFFFFFFFF


def lcg16(a, c, s, n):
    out = []
    for _ in range(n):
        s = (a * s + c) & M16
        out.append(s)
    return out


def xorshift16(s, n):
    if not s:
        s = 1
    out = []
    for _ in range(n):
        s ^= (s << 7) & M16; s ^= (s >> 9); s &= M16
        out.append(s)
    return out


def lfsr16(s, n, taps=(0, 2, 3, 5)):
    if not s:
        s = 1
    fb = 0
    for t in taps:
        fb |= 1 << t
    out = []
    for _ in range(n):
        bit = 0
        for t in taps:
            bit ^= (s >> t) & 1
        s = (s >> 1) | (bit << 15)
        out.append(s)
    return out


def lcg32_lo(a, c, s, n):
    out = []
    for _ in range(n):
        s = (a * s + c) & M32
        out.append(s & M16)
    return out


def lcg32_hi(a, c, s, n):
    out = []
    for _ in range(n):
        s = (a * s + c) & M32
        out.append((s >> 16) & M16)
    return out


SEEDS = {
    "V": lambda V, p, t: V & M16,
    "V>>16": lambda V, p, t: (V >> 16) & M16,
    "V^pt": lambda V, p, t: (V ^ p ^ t) & M16,
    "V*pt": lambda V, p, t: (V * (p ^ t)) & M16,
    "V+p+t": lambda V, p, t: (V + p + t) & M16,
    "V&0xff": lambda V, p, t: V & 0xFF,
    "(V>>8)&0xff": lambda V, p, t: (V >> 8) & 0xFF,
    "V*0x9e37>>16": lambda V, p, t: ((V * 0x9E3779B1) >> 16) & M16,
    "bswap16(V)": lambda V, p, t: struct.unpack(">H", struct.pack("<H", V & M16))[0],
}

LCG16_PARAMS = [
    (0x41C6, 0x3039, "msvc/bionic-ish"),
    (0x6C078965, 0x0001, "NR"),
    (16807, 0, "minstd"),
    (48271, 0, "minstd2"),
    (0x0805, 0x000B, "8bit-ish16"),
    (0x5D588B65, 0x0013, "randu-ish16"),
    (25173, 0, "msvc legacy"),
    (1103515245, 12345, "glibc low16"),
    (214013, 2531011, "msvc"),
    (0xB503, 0x0000, "unknown-1"),
    (0x41C6, 0x0000, "no-carry"),
    (0x0101, 0x0001, "x+1 mod 65536"),
    (0x8081, 0x0000, "x*32897"),
]

LFSR_TAPS = [(0, 2, 3, 5), (0, 1, 3, 12), (0, 1, 4, 6), (1, 3, 4), (0, 5, 7, 8)]


def main():
    rows = F.dedup(F.load_all())
    seen, uniq = set(), []
    for r in rows:
        k = (r["V"], r["pid"], r["tid"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    rows = uniq
    regu = []
    for r in rows:
        reg = r["d0"] + r["d2"] + r["d4"]
        regu.append([(reg[i] << 8) | reg[i + 1] for i in range(0, len(reg), 2)])
    n = len(rows)
    print("16-bit sweep over %d distinct (V,pid,tid) rows, %d region units" %
          (n, len(regu[0])))
    thr = max(3, n - 2)
    found = []

    def check(name, gen):
        cols = [gen(r["V"], r["pid"], r["tid"]) for r in rows]
        L = min(len(c) for c in cols)
        for j in range(L):
            for k in range(len(regu[0])):
                c = sum(1 for i in range(n) if cols[i][j] == regu[i][k])
                if c >= thr:
                    found.append((c, name, j, k))
                    print("  HIT %-30s out_unit=%d reg_unit=%d  %d/%d" %
                          (name, j, k, c, n))
    for sn, sf in SEEDS.items():
        for a, c, pn in LCG16_PARAMS:
            check("lcg16[a=%#x c=%#x %s][%s]" % (a, c, pn, sn),
                  lambda V, p, t, sf=sf, a=a, c=c: lcg16(a, c, sf(V, p, t) or 1, 256))
        check("xorshift16[%s]" % sn, lambda V, p, t, sf=sf: xorshift16(sf(V, p, t), 256))
        for taps in LFSR_TAPS:
            check("lfsr16%s[%s]" % (taps, sn),
                  lambda V, p, t, sf=sf, taps=taps: lfsr16(sf(V, p, t), 256, taps))
        for a, c in ((1103515245, 12345), (214013, 2531011), (1664525, 1013904223),
                     (0x6C078965, 1), (22695477, 1)):
            check("lcg32lo[a=%#x][%s]" % (a, sn),
                  lambda V, p, t, sf=sf, a=a, c=c: lcg32_lo(a, c, sf(V, p, t) or 1, 256))
            check("lcg32hi[a=%#x][%s]" % (a, sn),
                  lambda V, p, t, sf=sf, a=a, c=c: lcg32_hi(a, c, sf(V, p, t) or 1, 256))
    print("total hits: %d (threshold %d/%d)" % (len(found), thr, n))


if __name__ == "__main__":
    main()
