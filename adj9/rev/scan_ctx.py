#!/usr/bin/env python3
"""Scan the ctxcap5 stack dumps for the 26-pointer ctx marker array.

ctx = 26 x u64 pointers, ascending, all into ONE small region (~0x138 bytes,
i.e. libsigner .data va 0x151d18..0x151e50).  Since libsigner is dlopen'd and
unmapped after each signing, the pointed-to region may be unmapped now, but the
pointer VALUES survive on the stack.
"""
import os, struct, sys, glob, collections

D = os.path.join(os.path.dirname(__file__), "..", "device", "ctxcap5", "ctxcap5")
D = os.path.abspath(D)

def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]

def find_ctx(buf):
    """return list of (offset, [26 pointers])"""
    hits = []
    n = len(buf) - 8 * 26
    for off in range(0, n, 8):
        p = [u64(buf, off + 8 * i) for i in range(26)]
        # cheap rejects
        if p[0] < 0x1000:
            continue
        if not all(p[i] < p[i + 1] for i in range(25)):
            continue
        span = p[25] - p[0]
        if not (0x80 <= span <= 0x400):
            continue
        # all in the same 4 KiB page band (region is 312 B -> at most 2 pages)
        if (p[0] >> 12) != (p[25] >> 12) and ((p[25] >> 12) - (p[0] >> 12)) > 1:
            continue
        # deltas should be modest
        d = [p[i + 1] - p[i] for i in range(25)]
        if max(d) > 0x80:
            continue
        hits.append((off, p))
    return hits

def main():
    files = sorted(glob.glob(os.path.join(D, "*.bin")))
    print(f"scanning {len(files)} files in {D}")
    total = 0
    by_tid = collections.Counter()
    for f in files:
        with open(f, "rb") as fh:
            buf = fh.read()
        h = find_ctx(buf)
        if h:
            base = os.path.basename(f)
            total += len(h)
            for off, p in h:
                # tid = part after first underscore
                tid = base.split("_", 1)[1].rsplit(".", 1)[0]
                by_tid[tid] += 1
                print(f"{base} off=0x{off:04x} p0=0x{p[0]:x} span=0x{p[25]-p[0]:x} "
                      f"p25=0x{p[25]:x}")
    print(f"\ntotal hits: {total}")
    print("by tid:", dict(by_tid))

if __name__ == "__main__":
    main()
