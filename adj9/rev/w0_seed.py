"""w0_seed.py - is #0's 16-byte tile generated FROM W0 (same Random3, or the bionic
rand(3) generator, with W0 as the seed)?  W0 + tile are the only informative part of
#0 (slice 123), so a hit here would crack the largest piece of the 56-byte unknown.

Tested per sample over seed variants of W0 (as-is, high bit cleared, high bit set,
byte-reversed) and a couple of start offsets.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import Random3, M31

S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))


def words(x, n=5):
    raw = bytes.fromhex(x)
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


def bionic(seed, n=4000):
    """glibc TYPE_3 additive feedback, as used by bionic rand(); returns next()>>1."""
    r = [0] * 34
    st = seed & 0xFFFFFFFF
    if st == 0:
        st = 1
    r[0] = st if st < 2 ** 31 else st - 2 ** 32
    prev = r[0]
    for i in range(1, 31):
        hi = prev // 127773 if prev >= 0 else -((-prev) // 127773)
        lo = prev - hi * 127773
        w = 16807 * lo - 2836 * hi
        if w < 0:
            w += M31
        r[i] = prev = w
    f, b = 3, 0
    out = []
    for _ in range(n):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < 2 ** 31 else v - 2 ** 32
        out.append(v >> 1)
        f = (f + 1) % 31
        b = (b + 1) % 31
    return out


def rand_r(seed, n=4000):
    """rand_r-style (same recurrence, independent state per call)."""
    return bionic(seed, n)


print("%-3s %-9s %-9s %s" % ("i", "W0", "tile0", "result"))
hits = 0
for i, x in enumerate(S):
    w = words(x["d0"], 5)
    W0, tile = w[0], w[1:5]
    res = []
    seeds = {
        "W0": W0,
        "W0&7f": W0 & 0x7FFFFFFF,
        "W0|80": W0 | 0x80000000,
        "bswap": int.from_bytes(struct.pack(">I", W0), "little"),
        "W0^t": W0 ^ 0xFFFFFFFF,
    }
    for nm, sd in seeds.items():
        # Random3 stream
        R = Random3(sd)
        raw = [R.next() for _ in range(8000)]
        pairs = [raw[2 * k] ^ raw[2 * k + 1] for k in range(4000)]
        for snm, seq in (("r3raw", raw), ("r3pair", pairs)):
            if all(t in seq for t in tile):
                res.append((nm, snm, [seq.index(t) for t in tile]))
        # bionic streams
        for snm, seq in (("bionic", bionic(sd)), ("randr", rand_r(sd))):
            if all(t in seq for t in tile):
                res.append((nm, snm, [seq.index(t) for t in tile]))
        # seed from W0 xor-ed into the tile words? (quick check on first tile word)
    if res:
        hits += len(res)
    print("%-3d %08x %08x  %s" % (i, W0, tile[0], res if res else "none"))
print()
print("total tile-from-W0 hits:", hits)