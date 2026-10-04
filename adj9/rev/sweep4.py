import sys, struct, json, glob
sys.path.insert(0, ".")
from vm_final import Ex
from hydrate import rd32
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

d = json.load(open("..\\device\\vm_full.json"))
wh = [h for h in d if h.get("tag") == "workhorse"]
t = json.load(open("..\\device\\triples_fresh.json"))
body_live = bytes.fromhex([x for x in t if x[0] == "blob"][0][2])[16:]
live_dw = struct.unpack(">44I", body_live)
INBUF = int(wh[0]["x3"], 16) & MASK
X19LIVE = int(wh[0]["x19"], 16) & MASK
CTXLIVE = int(wh[0]["x20"], 16) & MASK

def build():
    ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
    for path in sorted(glob.glob("..\\device\\vm_mem\\R_*.bin")):
        base = int(path.split("R_")[1].split(".bin")[0], 16)
        data = open(path, "rb").read()
        for off in range(0, len(data) - 7, 8):
            v = struct.unpack("<Q", data[off:off + 8])[0]
            if v:
                ex.mem[base + off] = untag(v)
    cands = set()
    for va in list(ex.mem.keys()):
        if 0x6000000000 <= va < 0x8000000000 and (va & 7) == 0:
            c = rd32(ex.mem, va + 0x14)
            if 0 < c <= 512 and ex.mem.get((va + 0x18) & ~7, 0) != 0:
                cands.add(va)
    for va in cands:
        cnt = rd32(ex.mem, va + 0x14)
        dap = ex.mem.get((va + 0x18) & ~7, 0) & MASK
        ofp = ex.mem.get((va + 8) & ~7, 0) & MASK
        keep = {off: ex.mem.get((va + off) & ~7, 0) for off in (0x00, 0x08, 0x10, 0x18, 0x28)}
        s = ex.stream_for(va)
        s.data = [rd32(ex.mem, dap + 4 * j) for j in range(cnt)]
        s.offs = [0] + [rd32(ex.mem, ofp + 4 * j) for j in range(min(cnt + 4, 200))]
        for off, v in keep.items():
            ex.mem[(va + off) & ~7] = v
    return ex

def run_all(flag, sinkva):
    ex = build()
    ex.__dict__["_heap"] = [0x5A00000000, {}]
    ex.__dict__["_truesub"] = True
    X26 = 0x5A00002000
    ex.mem[X26] = sinkva
    if flag is not None:
        ex.mem[X19LIVE & ~7] = flag
    ex.R.update({"x21": 0, "x23": 0, "x26": X26})
    for h in wh:
        i = int(h["x1"], 16)
        ex.R.update({"x0": int(h["x0"], 16) & MASK, "x1": i,
                     "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
                     "x4": int(h["x4"], 16), "x9": int(h["x9"], 16),
                     "x19": X19LIVE, "x20": CTXLIVE,
                     "x30": 0xDEAD0000, "x29": ex.X29, "sp": INBUF})
        ex.pc = 0x12A880
        ex.run(max_steps=20000)
        ex.__dict__["_shadow"] = []
    best = (0, None)
    for va, s in ex.streams.items():
        for name, arr in (("data", s.data), ("offs", s.offs)):
            if len(arr) >= 44:
                for start in range(0, len(arr) - 44):
                    w = arr[start:start + 44]
                    mm = sum(1 for a, b in zip(w, live_dw) if (a & 0xFFFFFFFF) == b)
                    if mm > best[0]:
                        best = (mm, (hex(va), name, start))
    return best

if __name__ == "__main__":
    ex0 = build()
    cands = [va for va in ex0.streams if True]
    print("streams:", len(cands), flush=True)
    for flag in [None, 1]:
        for sinkva in cands[:14]:
            m, where = run_all(flag, sinkva)
            print("flag", flag, hex(sinkva), "->", m, where, flush=True)
