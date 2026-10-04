import sys, struct, json, glob
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

d = json.load(open("..\\device\\vm_full.json"))
wh = [h for h in d if h.get("tag") == "workhorse"][:44]
INBUF = int(wh[0]["x3"], 16) & MASK
ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
for path in sorted(glob.glob("..\\device\\vm_mem\\R_*.bin")):
    base = int(path.split("R_")[1].split(".bin")[0], 16)
    data = open(path, "rb").read()
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack("<Q", data[off:off + 8])[0]
        if v:
            ex.mem[base + off] = untag(v)
xs = [(int(h["x3"], 16) & 0xFFFFFFFF) for h in wh]
for i, w in enumerate(xs[1:], start=1):
    va = INBUF + (84 + i - 1) * 4
    a = va & ~7
    cur = ex.mem.get(a, 0)
    ex.mem[a] = ((cur & 0xFFFFFFFF00000000) | w) if (va & 7) == 0 else ((cur & 0xFFFFFFFF) | (w << 32))
ex.__dict__["_heap"] = [0x5A00000000, {}]
h = wh[0]
ex.R.update({"x0": int(h["x0"], 16) & MASK, "x1": 0,
             "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
             "x4": int(h["x4"], 16), "x9": int(h["x9"], 16),
             "x19": 0x6D9AC072B8, "x20": 0x6ED2ADE2D0,
             "x30": 0xDEAD0000, "x29": ex.X29, "sp": INBUF})
ex.pc = 0x12A880
st = ex.run(max_steps=30000)
print(st, ex.steps, "maxpc", hex(max(ex._pc_hist)))
print([(hex(p), c) for p, c in ex._pc_hist.most_common(5)])
print("queues:", {hex(k): v[:6] for k, v in ex.queues.items()})
calls = ex.__dict__.get("_calls", [])
print("calls:", len(calls))
for c in calls[:8]:
    print("  ", c[0], c[1], ["%x" % x for x in c[2]][:4])
