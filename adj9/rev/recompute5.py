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
print("inbuf", hex(INBUF), "outbuf", hex(OUTBUF))

ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
for path in sorted(glob.glob("..\\device\\vm_mem\\R_*.bin")):
    base = int(path.split("R_")[1].split(".bin")[0], 16)
    data = open(path, "rb").read()
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack("<Q", data[off:off + 8])[0]
        if v:
            ex.mem[base + off] = untag(v)
from hydrate import rd32
for _pass in range(2):
    for va in list(ex.mem):
        pass
    cands = set()
    for va in list(ex.mem.keys()):
        if 0x6000000000 <= va < 0x8000000000 and (va & 7) == 0:
            c = rd32(ex.mem, va + 0x14)
            if 0 < c <= 512:
                dap = ex.mem.get((va + 0x18) & ~7, 0) & MASK
                if dap != 0:
                    cands.add(va)
    for va in cands:
        cnt = rd32(ex.mem, va + 0x14)
        dap = ex.mem.get((va + 0x18) & ~7, 0) & MASK
        ofp = ex.mem.get((va + 8) & ~7, 0) & MASK
        s = ex.stream_for(va)
        s.data = [rd32(ex.mem, dap + 4 * j) for j in range(cnt)]
        s.offs = [0] + [rd32(ex.mem, ofp + 4 * j) for j in range(min(cnt + 4, 200))]
print("hydrated streams:", len([s for s in ex.streams.values() if s.data]))
xs = [(int(h["x3"], 16) & 0xFFFFFFFF) for h in wh]
for i, w in enumerate(xs[1:], start=1):
    va = INBUF + (84 + i - 1) * 4
    a = va & ~7
    cur = ex.mem.get(a, 0)
    ex.mem[a] = ((cur & 0xFFFFFFFF00000000) | w) if (va & 7) == 0 else ((cur & 0xFFFFFFFF) | (w << 32))
ex.mem[X19 & ~7] = ex.mem.get(X19 & ~7, 0)  # keep live flag (do not force)
X26 = 0x5A00002000
ex.mem[X26] = ex.mem.get(X26 & ~7, 0) or int(wh[1]["x0"], 16) & MASK
ex.__dict__["_heap"] = [0x5A00000000, {}]
for h in wh:
    i = int(h["x1"], 16)
    ex.R.update({"x0": int(h["x0"], 16) & MASK, "x1": i,
                 "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
                 "x4": int(h["x4"], 16), "x9": int(h["x9"], 16),
                 "x19": X19, "x20": CTX, "x21": 0, "x23": 0,
                 "x26": X26, "x30": 0xDEAD0000, "x29": ex.X29,
                 "sp": INBUF})
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
t = json.load(open("..\\device\\triples_fresh.json"))
blob = [x for x in t if x[0] == "blob"][0]
body_live = bytes.fromhex(blob[2])[16:]
m = sum(1 for a, b in zip(out, body_live) if a == b)
print("byte match:", m, "/176")
dw = sum(1 for k in range(44) if out[4*k:4*k+4] == body_live[4*k:4*k+4])
print("dword match:", dw, "/44")
print("mine:", out.hex()[:64])
print("live:", body_live.hex()[:64])
