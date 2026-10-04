"""_wordsens.py - which region words actually reach the body?

_perturb.py showed d4[0], d4[7] and d0[35] move NOTHING, while d0[0], d0[1],
d2[0], d8[0], d9[0] move many.  So the body's view of the region is a small
subset.  This scans every word of #0 (36), #2 (1) and #4 (8) one at a time and
reports how many of the 44 body words change.  The decoder only has to invert
the words that survive; the rest are unrecoverable BY CONSTRUCTION, which is
itself the answer to "what distinguishes genuine from synthetic".
"""
import json, struct, sys, time
sys.path.insert(0, ".")
from fin_vm2 import FinEx

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
asg = json.load(open("all_signings.json"))
ph3 = json.load(open("pair_h3.json"))


def descs_of(r):
    out = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data) // 4, 0, data))
    return out


def body(d, seed):
    ex = FinEx(seed, d)
    st = ex.run(max_steps=60_000_000)
    by = {}
    for (sva, n, v) in ex.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:
            by[n & 0xFFFFFFFF] = v & 0xFFFFFFFF
    return [by.get(i) for i in range(48)], st


i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
which = sys.argv[2] if len(sys.argv) > 2 else "all"
R = descs_of(asg[i])
seed = ph3[i]["second"]

TARGETS = []
if which in ("all", "d0"):
    TARGETS += [(0, w, "d0[%d]" % w) for w in range(36)]
if which in ("all", "d2"):
    TARGETS += [(4, 0, "d2[0]")]
if which in ("all", "d4"):
    TARGETS += [(3, w, "d4[%d]" % w) for w in range(8)]

t0 = time.time()
B0, st = body(R, seed)
print("base status=%s %.0fs" % (st, time.time() - t0), flush=True)
out = {}
for di, wi, lbl in TARGETS:
    d = [list(x) for x in R]
    n = d[di][0]
    if wi >= n:
        continue
    data = bytearray(d[di][2])
    old = struct.unpack_from(">I", bytes(data), 4 * wi)[0]
    struct.pack_into(">I", data, 4 * wi, old ^ 0x5A5A5A5A)
    d[di] = (n, 0, bytes(data))
    B1, st = body([tuple(x) for x in d], seed)
    ch = [j for j in range(4, 48) if B0[j] != B1[j]]
    out[lbl] = ch
    print("%-8s -> %2d/44 body words: %s" % (lbl, len(ch), ch), flush=True)
json.dump(out, open("_wordsens_%d.json" % i, "w"))
print("total %.0fs" % (time.time() - t0))
