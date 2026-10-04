"""fit_wordlaws.py - exhaustive per-word elementary-law search on the
avalanche part of the region (d0 words 0..35 and d4 words 0..7).

For every output word position we try a library of elementary functions of
(V, pid, tid) - both raw and byte-swapped - and report any that agree on ALL
sampled rows.  This is the "structured transform" hypothesis: if the VM's ALU
chain is a byteswap/XOR/multiply mixer rather than a standard PRF, some word
should fall out as a simple function.
"""
import hashlib
import struct
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fit_table as F

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def bswap32(x):
    return struct.unpack(">I", struct.pack("<I", x & M32))[0]


def bswap16(x):
    return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)


def fmix32(h):
    h &= M32
    h ^= h >> 16; h = (h * 0x85EBCA6B) & M32
    h ^= h >> 13; h = (h * 0xC2B2AE35) & M32
    h ^= h >> 16
    return h


def fmix64(h):
    h &= M64
    h ^= h >> 33; h = (h * 0xFF51AFD7ED558CCD) & M64
    h ^= h >> 33; h = (h * 0xC4CEB9FE1A85EC53) & M64
    h ^= h >> 33
    return h


def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & M64
    z = x
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return (z ^ (z >> 31)) & M64


def wang32(h):
    h = (~h + (h << 15)) & M32
    h ^= h >> 12; h = (h + (h << 2)) & M32
    h ^= h >> 4; h = (h * 2057) & M32
    h ^= h >> 16
    return h


def sm32(x):
    x = (x + 0x9E3779B9) & M32
    z = x
    z = ((z ^ (z >> 16)) * 0x21F0AAAD) & M32
    z = ((z ^ (z >> 15)) * 0x735A2D97) & M32
    return (z ^ (z >> 15)) & M32


def murmur3_32(data, seed=0):
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & M32
    l = len(data)
    for i in range(0, l // 4 * 4, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & M32; k = ((k << 15) | (k >> 17)) & M32; k = (k * c2) & M32
        h ^= k; h = ((h << 13) | (h >> 19)) & M32; h = (h * 5 + 0xE6546B64) & M32
    k = 0; r = l & 3
    if r >= 3: k ^= data[l - 1] << 16
    if r >= 2: k ^= data[l - 2] << 8
    if r >= 1: k ^= data[l - 3]
    if r >= 1:
        k = (k * c1) & M32; k = ((k << 15) | (k >> 17)) & M32; k = (k * c2) & M32; h ^= k
    h ^= l
    return fmix32(h)


BASE = {
    "V": lambda V, p, t: V & M32,
    "V^pid^tid": lambda V, p, t: (V ^ p ^ t) & M32,
    "V+pid+tid": lambda V, p, t: (V + p + t) & M32,
    "V-pid-tid": lambda V, p, t: (V - p - t) & M32,
    "V^pid": lambda V, p, t: (V ^ p) & M32,
    "V^tid": lambda V, p, t: (V ^ t) & M32,
    "V*pid^tid": lambda V, p, t: (V * (p ^ t)) & M32,
    "pid^tid": lambda V, p, t: (p ^ t) & M32,
    "pid": lambda V, p, t: p & M32,
    "tid": lambda V, p, t: t & M32,
    "V,pid,tid64": lambda V, p, t: ((V << 32) | (p << 16) | t) & M64,
    "V<<16": lambda V, p, t: (V << 16) & M64,
    "V*0x9e3779b1": lambda V, p, t: (V * 0x9E3779B1) & M32,
    "V+0x9e3779b9": lambda V, p, t: (V + 0x9E3779B9) & M32,
    "V*0x45d9f3b": lambda V, p, t: (V * 0x45D9F3B) & M32,
    "V^0xa5a5a5a5": lambda V, p, t: (V ^ 0xA5A5A5A5) & M32,
    "V^(V>>16)": lambda V, p, t: (V ^ (V >> 16)) & M32,
    "(V+1)*0x45d9f3b": lambda V, p, t: ((V + 1) * 0x45D9F3B) & M32,
    "V^(pid<<16)": lambda V, p, t: (V ^ ((p & 0xFFFF) << 16)) & M32,
    "V^(tid<<16)": lambda V, p, t: (V ^ ((t & 0xFFFF) << 16)) & M32,
    "V^(pid*tid)": lambda V, p, t: (V ^ ((p * t) & M32)) & M32,
}

MIX = {
    "id": lambda x: x & M32,
    "bswap": lambda x: bswap32(x),
    "fmix32": lambda x: fmix32(x),
    "wang": lambda x: wang32(x),
    "sm32": lambda x: sm32(x),
    "fmix32^bswap": lambda x: bswap32(fmix32(x)),
    "fmix32rot16": lambda x: ((fmix32(x) << 16) | (fmix32(x) >> 16)) & M32,
    "fmix64lo": lambda x: fmix64(x) & M32,
    "fmix64hi": lambda x: (fmix64(x) >> 32) & M32,
    "sm64lo": lambda x: splitmix64(x) & M32,
    "sm64hi": lambda x: (splitmix64(x) >> 32) & M32,
    "sm64_2lo": lambda x: splitmix64(splitmix64(x)) & M32,
    "bs(fmix64lo)": lambda x: bswap32(fmix64(x) & M32),
    "mul_bswap": lambda x: (x * 0x01000193) & M32,
    "xorshift": lambda x: (lambda y: y ^ (y >> 16))((x * 2654435761) & M32),
}


def candidates():
    for bn, bf in BASE.items():
        yield ("%s|raw" % bn, lambda V, p, t, bf=bf: bf(V, p, t))
        for mn, mf in MIX.items():
            if mn == "id":
                continue
            yield ("%s|%s" % (bn, mn),
                   lambda V, p, t, bf=bf, mf=mf: mf(bf(V, p, t)))
        # 16-bit halves recombined
        yield ("%s|hi^lo" % bn,
               lambda V, p, t, bf=bf: ((bf(V, p, t) >> 16) ^ (bf(V, p, t) & 0xFFFF)) & M32)
        yield ("%s|lo|hi" % bn,
               lambda V, p, t, bf=bf: ((bf(V, p, t) & 0xFFFF) << 16 | (bf(V, p, t) >> 16)) & M32)


def hash_candidates():
    for order in (">I", "<I"):
        for hn, hf in (("sha256", hashlib.sha256), ("sha1", hashlib.sha1),
                       ("md5", hashlib.md5)):
            for pre in ("", "pid,tid,"):
                def g(V, p, t, hf=hf, order=order, pre=pre):
                    data = (struct.pack(">II", p, t) if pre else b"") + \
                           struct.pack(order, V & M32)
                    d = hf(data).digest()
                    return int.from_bytes(d[:4], "big")
                yield ("%s(%sV%s)" % (hn, pre, order), g)
            def g2(V, p, t, hf=hf, order=order):
                d = hf(struct.pack(order, V & M32)).digest()
                return int.from_bytes(d[4:8], "big")
            yield ("%s(%sV)[4:8]" % (hn, order), g2)
    for order in ("<I", ">I"):
        yield ("murmur3(%sV)" % order,
               lambda V, p, t, order=order: murmur3_32(struct.pack(order, V & M32)))


def main():
    rows = F.dedup(F.load_all())
    seen, uniq = set(), []
    for r in rows:
        k = (r["V"], r["pid"], r["tid"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    rows = uniq
    n = len(rows)
    print("per-word law search over %d rows" % n)
    words = []
    for r in rows:
        w = r["w0"] + r["d4w"]
        words.append(w)
    NW = 44  # 36 d0 + 8 d4
    cands = list(candidates()) + list(hash_candidates())
    print("%d candidate functions x %d word positions" % (len(cands), NW))
    hits = []
    for j in range(NW):
        col = [words[i][j] for i in range(n)]
        for cn, cf in cands:
            if all(cf(rows[i]["V"], rows[i]["pid"], rows[i]["tid"]) == col[i]
                   for i in range(n)):
                hits.append((j, cn))
                print("  FULL HIT word[%2d] <- %s" % (j, cn))
    if not hits:
        print("no word is an elementary function of (V,pid,tid) on all %d rows" % n)
    # partial: how many rows does the best candidate match per word
    best = []
    for j in range(NW):
        col = [words[i][j] for i in range(n)]
        bc = 0; bn = ""
        for cn, cf in cands:
            c = sum(1 for i in range(n) if cf(rows[i]["V"], rows[i]["pid"], rows[i]["tid"]) == col[i])
            if c > bc:
                bc, bn = c, cn
        best.append((bc, j, bn))
    best.sort(reverse=True)
    print("\nbest partial matches (chance for 32-bit = %d/%d):" % (0, n))
    for c, j, bn in best[:8]:
        print("  word[%2d] %-28s %d/%d" % (j, bn, c, n))


if __name__ == "__main__":
    main()
