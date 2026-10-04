# scan the 45 slow-burst stack dumps with the CORRECT base
# maps line: 6f1569a000-6f157e3000 r-xp 00054000 split_config.arm64_v8a.apk
# => libbase = 0x6f1569a000 (VA 0), text 0x8be0..0x1489b4, size 0x149000
import glob, struct, os
import numpy as np

BASE = 0x6f1569a000
TA, TS = 0x8be0, 0x149000
LO, HI = BASE + TA, BASE + TA + TS

files = sorted(glob.glob(os.path.join(os.path.dirname(__file__), '..', 'device', 'st_out', '*.bin')))
print("files:", len(files))

# collect return addresses (8-byte words that point into .text)
retc = {}
anchor_hits = 0
tot = 0
for f in files:
    buf = open(f, 'rb').read()
    tot += len(buf)
    a = np.frombuffer(buf, dtype='<u8')
    m = (a >= LO) & (a < HI)
    for v in a[m]:
        v = int(v)
        va = v - BASE
        if va & 3 == 0 and va >= 4:
            retc[va - 4] = retc.get(va - 4, 0) + 1

    # anchor scan (ctx detector): 16 u16 with high-bit permutation 0..15
    h = np.frombuffer(buf, dtype='<u2')
    if len(h) >= 16:
        POW = (1 << np.arange(16)).astype(np.uint32)
        TGT = np.arange(16, dtype=np.int16)
        hb = np.searchsorted(POW, h.astype(np.uint32), side='right').astype(np.int16) - 1
        ws = np.lib.stride_tricks.sliding_window_view(hb, 16)
        hits = np.nonzero(np.all(np.sort(ws, axis=1) == TGT, axis=1))[0]
        anchor_hits += len(hits)

print("scanned bytes: %.1f MB" % (tot / 1e6))
print("distinct bl return VAs:", len(retc))
for va, c in sorted(retc.items(), key=lambda kv: -kv[1])[:30]:
    print("  VA 0x%06x  x%d" % (va, c))

print("ANCHOR hits (ctx model):", anchor_hits)

# also probe the specific ctx-path addrs
probes = [0xdb164, 0x1437c8, 0x1437bc, 0x143794, 0x143c88, 0x144214, 0x1441e4]
for p in probes:
    print("probe 0x%06x: %d" % (p, retc.get(p, 0)))
