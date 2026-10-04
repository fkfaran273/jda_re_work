#!/usr/bin/env python
"""Can we reproduce the leading bytes of the 192-byte blob from the timestamp?

Hypothesis: nSign does  srand(time(NULL))  then draws rand() to build the blob
(nonce / keystream). Evidence: the ONLY two blobs that share a prefix (16 bytes)
are the only two that completed inside the same wall-clock second.

libsigner.so imports rand+srand+time+gettimeofday and nothing cryptographic.

We try several PRNG implementations (glibc TYPE_3 additive-feedback and the
classic LCGs used by bionic), several byte-extraction rules, and a +/-8s
window around each blob's logged timestamp.
"""
import io, os, re, glob, struct

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.normpath(os.path.join(HERE, "..", "cap"))
M32 = 0xFFFFFFFF


def glibc_rand(seed, n):
    """glibc TYPE_3 additive feedback generator. Yields n 31-bit outputs."""
    r = [0] * (344 + n)
    r[0] = seed & M32
    for i in range(1, 31):
        v = (16807 * r[i - 1]) % 2147483647
        r[i] = v & M32
    for i in range(31, 34):
        r[i] = r[i - 31]
    for i in range(34, 344 + n):
        r[i] = (r[i - 31] + r[i - 3]) & M32
    for i in range(344, 344 + n):
        yield r[i] >> 1


def lcg_glibc(seed, n):
    """s = (s*1103515245 + 12345) mod 2^31 ; out = s"""
    s = seed & 0x7FFFFFFF
    for _ in range(n):
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
        yield s


def lcg_hi16(seed, n):
    """classic: out = (s >> 16) & 0x7fff"""
    s = seed & M32
    for _ in range(n):
        s = (s * 1103515245 + 12345) & M32
        yield (s >> 16) & 0x7FFF


def lcg_bsd(seed, n):
    s = seed & M32
    for _ in range(n):
        s = (s * 1103515245 + 12345) & M32
        yield (s >> 16) & 0x7FFFFFFF


PRNGS = {
    "glibc_type3": glibc_rand,
    "lcg_31": lcg_glibc,
    "lcg_hi15": lcg_hi16,
    "lcg_hi31": lcg_bsd,
}


def extractors(vals, nbytes):
    """several ways of turning 31-bit rand() outputs into bytes"""
    out = {}
    v = vals[:max(64, nbytes * 2)]
    out["low8"] = bytes(x & 0xFF for x in v)[:nbytes]
    out["b8_8"] = bytes((x >> 8) & 0xFF for x in v)[:nbytes]
    out["b16_8"] = bytes((x >> 16) & 0xFF for x in v)[:nbytes]
    out["b23_8"] = bytes((x >> 23) & 0xFF for x in v)[:nbytes]
    out["le32"] = b"".join(struct.pack("<I", x & M32) for x in v)[:nbytes]
    out["be32"] = b"".join(struct.pack(">I", x & M32) for x in v)[:nbytes]
    out["le32_s1"] = b"".join(struct.pack("<I", (x << 1) & M32) for x in v)[:nbytes]
    out["mod256"] = bytes(x % 256 for x in v)[:nbytes]
    return out


def main():
    blobs = []
    for f in sorted(glob.glob(os.path.join(CAP, "*.log"))):
        t = open(f, encoding="utf8", errors="replace").read()
        for ty, ts, body in re.findall(
                r"###ADJ9_BEGIN type=(\S+) utf8len=\d+ ts=(\d+)\ntext: (.*?)\n###ADJ9_END", t, re.S):
            if ty != "nsign":
                continue
            h = re.search(r"^hex=([0-9a-fA-F]+)", body, re.M)
            if not h or len(h.group(1)) != 384:
                continue
            blobs.append((int(ts), bytes.fromhex(h.group(1)), os.path.basename(f)))
    blobs.sort()

    out = io.open(os.path.join(HERE, "predict_rand.txt"), "w", encoding="utf8")
    out.write("blobs with timestamps: %d\n\n" % len(blobs))

    best = {}
    for ts, blob, src in blobs:
        sec = ts // 1000
        hit = None
        for pname, fn in PRNGS.items():
            for d in range(-8, 9):
                seed = sec + d
                vals = list(fn(seed, 96))
                for ename, cand in extractors(vals, 32).items():
                    for n in (4, 8, 12, 16):
                        if cand[:n] == blob[:n] and n >= 8:
                            key = (pname, ename)
                            best.setdefault(key, []).append((src, ts, d, n))
                            hit = (pname, ename, d, n)
        if hit:
            out.write("MATCH %s: %s/%s seed_delta=%d matched=%dB\n" % (src, hit[0], hit[1], hit[2], hit[3]))

    out.write("\n=== summary: (prng, extractor) -> number of blobs matched >=8B ===\n")
    if not best:
        out.write("  NONE\n")
    for k in sorted(best, key=lambda x: -len(best[x])):
        rows = best[k]
        out.write("  %-28s %d blobs   e.g. %s\n" % (str(k), len(rows), rows[:3]))
    out.close()
    print(open(os.path.join(HERE, "predict_rand.txt"), encoding="utf8").read())


if __name__ == "__main__":
    main()
