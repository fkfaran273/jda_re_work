import sys, struct, json, glob
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

d = json.load(open("..\\device\\vm_full.json"))
wh = [h for h in d if h.get("tag") == "workhorse"][:44]
INBUF = 0x6D9C62CE88
OUTBUF = 0x6E62A0CE70
X0 = int(wh[0]["x0"], 16) & MASK
CTX = 0x6ED2ADA4F0  # live x20 (untagged guess)

ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
# stock vm_mem files
for path in sorted(glob.glob("..\\device\\vm_mem\\R_*.bin")):
    base = int(path.split("R_")[1].split(".bin")[0], 16)
    data = open(path, "rb").read()
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack("<Q", data[off:off + 8])[0]
        if v:
            ex.mem[base + off] = untag(v)
# stock input words 84..126 from logged x3 stream
xs = [(int(h["x3"], 16) & 0xFFFFFFFF) for h in wh]
for i, w in enumerate(xs[1:], start=1):
    va = INBUF + (84 + i - 1) * 4
    a = va & ~7
    cur = ex.mem.get(a, 0)
    if (va & 7) == 0:
        cur = (cur & 0xFFFFFFFF00000000) | w
    else:
        cur = (cur & 0xFFFFFFFF) | (w << 32)
    ex.mem[a] = cur
print("inbuf words stocked:", len(xs) - 1)
# run 44 workhorse calls
ex.__dict__["_heap"] = [0x5A00000000, {}]
for h in wh:
    i = int(h["x1"], 16)
    ex.R.update({"x0": int(h["x0"], 16) & MASK, "x1": i,
                 "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
                 "x4": int(h["x4"], 16), "x19": 0x6D9C62CE88,
                 "x20": CTX, "x30": 0xDEAD0000, "x29": ex.X29,
                 "sp": 0x6D9C62CE88})
    ex.pc = 0x12A880
    st = ex.run(max_steps=200000)
    if st != "ret" and i < 3:
        print("iter", i, "exit:", st, ex.steps)
    ex.__dict__["_shadow"] = []
print("done")
out = b""
for k in range(44):
    a = (OUTBUF + k * 4) & ~7
    w = ex.mem.get(a, 0)
    word = (w & 0xFFFFFFFF) if ((OUTBUF + k * 4) & 7) == 0 else (w >> 32) & 0xFFFFFFFF
    out += struct.pack(">I", word)
open("body_recomputed.bin", "wb").write(out)
print("body bytes:", len(out), out.hex()[:64])
