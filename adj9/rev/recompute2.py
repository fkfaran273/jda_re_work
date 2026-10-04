import sys, struct, json, glob
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

d = json.load(open("..\\device\\vm_full.json"))
wh = [h for h in d if h.get("tag") == "workhorse"][:44]
INBUF = int(wh[0]["x3"], 16) & MASK
OUTBUF = int(wh[0]["x2"], 16) & MASK
X0 = int(wh[0]["x0"], 16) & MASK
CTX = int(wh[0]["x20"], 16) & MASK
X19 = int(wh[0]["x19"], 16) & MASK
print("inbuf", hex(INBUF), "outbuf", hex(OUTBUF), "ctx", hex(CTX))

ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
for path in sorted(glob.glob("..\\device\\vm_mem\\R_*.bin")):
    base = int(path.split("R_")[1].split(".bin")[0], 16)
    data = open(path, "rb").read()
    n = 0
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack("<Q", data[off:off + 8])[0]
        if v:
            ex.mem[base + off] = untag(v)
            n += 1
    print(path, n)
xs = [(int(h["x3"], 16) & 0xFFFFFFFF) for h in wh]
for i, w in enumerate(xs[1:], start=1):
    va = INBUF + (84 + i - 1) * 4
    a = va & ~7
    cur = ex.mem.get(a, 0)
    ex.mem[a] = ((cur & 0xFFFFFFFF00000000) | w) if (va & 7) == 0 else ((cur & 0xFFFFFFFF) | (w << 32))
print("inbuf words:", len(xs) - 1)
ex.__dict__["_heap"] = [0x5A00000000, {}]
for h in wh:
    i = int(h["x1"], 16)
    ex.R.update({"x0": int(h["x0"], 16) & MASK, "x1": i,
                 "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
                 "x4": int(h["x4"], 16), "x9": int(h["x9"], 16),
                 "x19": X19, "x20": CTX, "x30": 0xDEAD0000,
                 "x29": ex.X29, "sp": INBUF})
    ex.pc = 0x12A880
    st = ex.run(max_steps=200000)
    if i < 2:
        print("iter", i, "exit:", st, ex.steps)
    ex.__dict__["_shadow"] = []
out = b""
for k in range(44):
    a = (OUTBUF + k * 4) & ~7
    w = ex.mem.get(a, 0)
    word = (w & 0xFFFFFFFF) if ((OUTBUF + k * 4) & 7) == 0 else (w >> 32) & 0xFFFFFFFF
    out += struct.pack(">I", word)
open("body_v2.bin", "wb").write(out)
print("body:", out.hex()[:64])
