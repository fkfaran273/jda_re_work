"""seed_sweep.py - find (seed, rand_impl, pre-advance k) reproducing the
captured device signing headers (4 pair-XOR units each, 3 signings = 12
consecutive pair units in one process).

Usage: python seed_sweep.py [kmax] [seed_lo_off] [seed_hi_off]
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

MASK48 = (1 << 48) - 1


def l48_stream(seed):
    """bionic/glibc srand48+lrand48"""
    s = ((seed & 0xFFFFFFFF) << 16 | 0x330E) & MASK48
    while True:
        s = (s * 0x5DEECE66D + 0xB) & MASK48
        yield s >> 17


def ansi_stream(seed):
    s = seed & 0x7FFFFFFF
    while True:
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
        yield s


def random3_stream(seed):
    """bionic rand() = random() = BSD TYPE_3 (the proven header law)."""
    M31 = 2147483647
    r = [0] * 31
    s = seed & 0xFFFFFFFF or 1
    w = s if s < 2 ** 31 else s - 2 ** 32
    r[0] = w
    for i in range(1, 31):
        hi, lo = divmod(w, 127773)
        w = 16807 * lo - 2836 * hi
        if w < 0:
            w += M31
        r[i] = w
    f, b = 3, 0
    for _ in range(310):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < 2 ** 31 else v - 2 ** 32
        f = (f + 1) % 31
        b = (b + 1) % 31
    while True:
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        f = (f + 1) % 31
        b = (b + 1) % 31
        yield o


def main():
    kmax = int(sys.argv[1]) if len(sys.argv) > 1 else 500_000
    lo = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    hi = int(sys.argv[3]) if len(sys.argv) > 3 else 8

    d = json.load(open(os.path.join(
        HERE, "..", "device", "java_dump", "signings_extract.json")))["signings"]
    units = []          # per signing: 4 u32 BE words of blob[0:16]
    for row in d:
        b = bytes.fromhex(row["blob"])
        units.append([struct.unpack_from(">I", b, 4 * i)[0] for i in range(4)])
    print("device units:")
    for i, u in enumerate(units):
        print("  signing%d: %s" % (i + 1, " ".join("%08x" % v for v in u)))

    sec1 = d[0]["ts"] // 1000
    seeds = [sec1 + o for o in range(-lo, hi + 1)]
    impls = {"random3": random3_stream, "lrand48": l48_stream, "ansi": ansi_stream}

    base_sec = 1789240512  # also test the harness clock base? no - device second
    for name, mk in impls.items():
        for seed in seeds:
            g = mk(seed)
            prev = []
            hits = []
            for k in range(kmax):
                r = next(g)
                prev.append(r)
                if len(prev) > 24:
                    prev.pop(0)
                if len(prev) >= 2 and (prev[-2] ^ prev[-1]) == units[0][0]:
                    # candidate: check all 12 pairs from position k-1
                    st = max(0, len(prev) - 2)
                    hits.append(k - 1)
                # full check when we have 24 draws ending here and first pair matches
                if len(prev) == 24 and (prev[0] ^ prev[1]) == units[0][0]:
                    ok1 = all((prev[2 * j] ^ prev[2 * j + 1]) == units[0][j]
                              for j in range(4))
                    if ok1:
                        print("  %s seed=%d SIGNING1 FULL MATCH at k=%d"
                              % (name, seed, k - 23))
            # second pass for full 3-signing check on stored candidates
            for k0 in hits:
                g2 = mk(seed)
                draws = [next(g2) for _ in range(k0 + 25)]
                window = draws[k0:k0 + 24]
                want = [u for uu in units for u in uu]
                got = [window[2 * j] ^ window[2 * j + 1] for j in range(12)]
                nmatch = sum(1 for a, b in zip(got, want) if a == b)
                if nmatch >= 2:
                    print("  %s seed=%d k=%d: %d/12 units match  got=%s"
                          % (name, seed, k0, nmatch,
                             " ".join("%08x" % v for v in got)))
                if nmatch == 12:
                    print("  *** FULL 3-SIGNING MATCH: seed=%d impl=%s k=%d ***"
                          % (seed, name, k0))
    print("sweep done (kmax=%d, seeds %d..%d)" % (kmax, sec1 - lo, sec1 + hi))


if __name__ == "__main__":
    main()
