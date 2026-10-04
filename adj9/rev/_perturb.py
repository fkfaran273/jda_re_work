"""_perturb.py - how many body words change when ONE region word changes?
If the body is a per-word (or few-word) bijection of the region plane, a single
region-word perturbation moves 1-2 body words -> the decoder is then a fixed
table/algebra.  If all 44 move, the body is a hash-like mix (no cheap invert).
"""
import json, struct, sys, time
sys.path.insert(0, ".")
from fin_vm2 import FinEx

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
IDX_OF = {b: k for k, b in enumerate(VA_ORDER)}
asg = json.load(open("all_signings.json"))
ph3 = json.load(open("pair_h3.json"))


def descs_of(r):
    out = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data) // 4, 0, data))
    return out


def body(d, seed, steps=60_000_000):
    ex = FinEx(seed, d)
    st = ex.run(max_steps=steps)
    by = {}
    for (sva, n, v) in ex.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:
            by[n & 0xFFFFFFFF] = v & 0xFFFFFFFF
    return [by.get(i) for i in range(48)], st, ex.nrand


i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
r = asg[i]
seed = ph3[i]["second"]
base_d = descs_of(r)

# descriptor words we perturb: (desc_index_in_VA_ORDER, word_index, label)
TESTS = [(0, 0, "d0[0]"), (0, 1, "d0[1]"), (0, 35, "d0[35]"),
         (4, 0, "d2[0]"), (3, 0, "d4[0]"), (3, 7, "d4[7]"),
         (1, 0, "d9[0]"), (2, 0, "d8[0]")]

t0 = time.time()
B0, st, nr = body(base_d, seed)
print("base status=%s nrand=%d %.0fs" % (st, nr, time.time() - t0), flush=True)

# also: does the SECOND alone move the body (region held fixed)?
B0b, st, _ = body(base_d, seed + 1)
ch = [j for j in range(48) if B0[j] != B0b[j]]
print("second+1 (same region): changed %d/48 %s" % (len(ch), ch), flush=True)

for di, wi, lbl in TESTS:
    d = [list(x) for x in base_d]
    n = d[di][0]
    if wi >= n:
        print("%-8s skip (len %d)" % (lbl, n))
        continue
    data = bytearray(d[di][2])
    old = struct.unpack_from(">I", bytes(data), 4 * wi)[0]
    struct.pack_into(">I", data, 4 * wi, (old ^ 0x5A5A5A5A) & 0xFFFFFFFF)
    d[di] = (n, 0, bytes(data))
    B1, st, _ = body([tuple(x) for x in d], seed)
    ch = [j for j in range(4, 48) if B0[j] != B1[j]]
    print("%-8s old=%08x  body changed %2d/44 %s" % (lbl, old, len(ch), ch), flush=True)
