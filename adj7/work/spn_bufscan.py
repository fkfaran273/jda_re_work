"""spn_bufscan.py — find ALL stride-4 byte-buffer fills in v3_writes.txt:
single-byte 4-byte stores to consecutive cells.  Map them to chunk outputs.

    python spn_bufscan.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
body = blob[16:272]
chunks = [body[16 * k:16 * k + 16] for k in range(16)]

# stream: keep byte-value stores (size 4, value < 0x100, heap addr)
# too many tag writes; instead detect runs online: keep last stores per addr
# Simplest robust approach: collect (idx, addr, val) for val<0x100 stores,
# excluding the noisy tag cells seen everywhere (0x90051e0 etc.) — no, keep
# all; we scan for 16-length runs afterwards.
events = []
n = 0
with open(os.path.join(HERE, "v3_writes.txt")) as f:
    for ln in f:
        n += 1
        p = ln.split()
        if len(p) < 3:
            continue
        a = int(p[0], 16)
        if a < 0x9000000:
            continue
        s = int(p[1])
        if s != 4:
            continue
        v = int(p[2], 16)
        if v < 0x100:
            events.append((n, a, v))
print("total lines", n, "byte-store events", len(events))

# index by (addr -> list of (idx, val))
from collections import defaultdict
by_addr = defaultdict(list)
for idx, a, v in events:
    by_addr[a].append((idx, v))

# for each chunk, try to find A such that chunk bytes stored at A+4j in order
found = []
for k, ch in enumerate(chunks):
    b0 = ch[0]
    for idx0, a0, v0 in events:
        if v0 != b0:
            continue
        ok = True
        idxs = [idx0]
        for j in range(1, 16):
            tgt = ch[j]
            lst = by_addr.get(a0 + 4 * j, [])
            hit = None
            for i2, v2 in lst:
                if v2 == tgt and i2 > idxs[-1] and i2 - idxs[-1] < 5000:
                    hit = i2
                    break
            if hit is None:
                ok = False
                break
            idxs.append(hit)
        if ok:
            found.append((k, a0, idxs))
            print("chunk %2d buffer at %#x, stores at %s"
                  % (k, a0, idxs))
            break
    else:
        print("chunk %2d: no stride-4 fill found" % k)
print("done")
