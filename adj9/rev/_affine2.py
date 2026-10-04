"""_affine2.py - is body = M . region (+c) an AFFINE map?

If yes the decoder is linear algebra: body is 44 words = 1408 bits out of the
36 region words = 1152 bits (over-determined), so the region inverts by Gaussian
elimination, and S = bswap32(d2) falls out for free.

Test (6 FinEx runs):
  R, Ra = R with d0[0] bit0 flipped, Rb = bit1 flipped, Rab = both,
  R2 = a different region, R2a = R2 with d0[0] bit0 flipped.
Checks
  (1) XOR-affine:   B(Rab) ^ B(Ra) ^ B(Rb) ^ B(R)  == 0
  (2) ADD-affine:   B(Rab)-B(Ra)-B(Rb)+B(R)      == 0  (mod 2^32)
  (3) base-independence of the d0[0]-bit0 delta:  B(Ra)^B(R) == B(R2a)^B(R2)
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


def patch(d, di, wi, mask):
    d = [list(x) for x in d]
    n = d[di][0]
    data = bytearray(d[di][2])
    old = struct.unpack_from(">I", bytes(data), 4 * wi)[0]
    struct.pack_into(">I", data, 4 * wi, old ^ mask)
    d[di] = (n, 0, bytes(data))
    return [tuple(x) for x in d], old


i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
R = descs_of(asg[i])
seed = ph3[i]["second"]
Ra, v0 = patch(R, 0, 0, 1 << 0)
Rb, _ = patch(R, 0, 0, 1 << 1)
Rab, _ = patch(R, 0, 0, (1 << 0) | (1 << 1))
# R2: flip a different d0 word so the base state differs
R2, _ = patch(R, 0, 5, 0xA5A5A5A5)
R2a, _ = patch(R2, 0, 0, 1 << 0)

t0 = time.time()
B = {}
for name, dd in (("R", R), ("Ra", Ra), ("Rb", Rb), ("Rab", Rab), ("R2", R2), ("R2a", R2a)):
    b, st = body(dd, seed)
    B[name] = b
    print("%-4s status=%s %.0fs" % (name, st, time.time() - t0), flush=True)

M = 0xFFFFFFFF
xor_res = [(B["Rab"][k] ^ B["Ra"][k] ^ B["Rb"][k] ^ B["R"][k]) & M for k in range(4, 48)]
add_res = [(B["Rab"][k] - B["Ra"][k] - B["Rb"][k] + B["R"][k]) & M for k in range(4, 48)]
print("d0[0] base=%08x" % v0)
print("XOR-affine residual zero at %d/44 words" % sum(1 for x in xor_res if x == 0))
print("  nonzero:", [(4 + k, "%08x" % x) for k, x in enumerate(xor_res) if x][:8])
print("ADD-affine residual zero at %d/44 words" % sum(1 for x in add_res if x == 0))
print("  nonzero:", [(4 + k, "%08x" % x) for k, x in enumerate(add_res) if x][:8])
same = sum(1 for k in range(4, 48)
           if (B["Ra"][k] ^ B["R"][k]) == (B["R2a"][k] ^ B["R2"][k]))
print("d0[0]-bit0 delta base-independent at %d/44 words" % same)
d1 = [(B["Ra"][k] ^ B["R"][k]) & M for k in range(4, 48)]
d2_ = [(B["R2a"][k] ^ B["R2"][k]) & M for k in range(4, 48)]
print("  delta1:", " ".join("%08x" % x for x in d1[:10]))
print("  delta2:", " ".join("%08x" % x for x in d2_[:10]))
