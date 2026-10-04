import sys, struct, json, glob, itertools
sys.path.insert(0, ".")
from vm_final import Ex
from hydrate import rd32
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

d = json.load(open("..\\device\\vm_full.json"))
wh = [h for h in d if h.get("tag") == "workhorse"][:44]
t = json.load(open("..\\device\\triples_fresh.json"))
body_live = bytes.fromhex([x for x in t if x[0] == "blob"][0][2])[16:]
live_dw = struct.unpack(">44I", body_live)
INBUF = int(wh[0]["x3"], 16) & MASK
X19LIVE = int(wh[0]["x19"], 16) & MASK
CTXLIVE = int(wh[0]["x20"], 16) & MASK
xs = [(int(h["x3"], 16) & 0xFFFFFFFF) for h in wh]

def build():
    ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
    for path in sorted(glob.glob("..\\device\\vm_mem\\R_*.bin")):
        base = int(path.split("R_")[1].split(".bin")[0], 16)
        data = open(path, "rb").read()
        for off in range(0, len(data) - 7, 8):
            v = struct.unpack("<Q", data[off:off + 8])[0]
            if v:
                ex.mem[base + off] = untag(v)
    for i, w in enumerate(xs[1:], start=1):
        va = INBUF + (84 + i - 1) * 4
        a = va & ~7
        cur = ex.mem.get(a, 0)
        ex.mem[a] = ((cur & 0xFFFFFFFF00000000) | w) if (va & 7) == 0 else ((cur & 0xFFFFFFFF) | (w << 32))
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
        s = ex.stream_for(va)
        s.data = [rd32(ex.mem, dap + 4 * j) for j in range(cnt)]
        s.offs = [0] + [rd32(ex.mem, ofp + 4 * j) for j in range(min(cnt + 4, 200))]
    return ex

def score(ex):
    best = (0, None)
    for va, s in ex.streams.items():
        for name, arr in (("data", s.data), ("offs", s.offs)):
            if len(arr) >= 44:
                for start in [0, len(arr) - 44]:
                    w = arr[start:start + 44]
                    m = sum(1 for a, b in zip(w, live_dw) if (a & 0xFFFFFFFF) == b)
                    if m > best[0]:
                        best = (m, (hex(va), name, start))
    return best

results = []
for flag, x26t in itertools.product([0, 1, 8], ["main", "ctx", "zero"]):
    ex = build()
    ex.__dict__["_heap"] = [0x5A00000000, {}]
    X26 = 0x5A00002000
    mains = [va for va, s in ex.streams.items() if len(s.data) > 80]
    tgt = {"main": (mains[0] if mains else 0), "ctx": CTXLIVE, "zero": 0}[x26t]
    ex.mem[X26] = tgt
    ex.mem[X19LIVE & ~7] = flag
    for h in wh:
        i = int(h["x1"], 16)
        ex.R.update({"x0": int(h["x0"], 16) & MASK, "x1": i,
                     "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
                     "x4": int(h["x4"], 16), "x9": int(h["x9"], 16),
                     "x19": X19LIVE, "x20": CTXLIVE, "x21": 0, "x23": 0,
                     "x26": X26, "x30": 0xDEAD0000, "x29": ex.X29, "sp": INBUF})
        ex.pc = 0x12A880
        ex.run(max_steps=200000)
        ex.__dict__["_shadow"] = []
    m, where = score(ex)
    results.append((m, flag, x26t, where))
    print("flag", flag, "x26", x26t, "->", m, where)
print("BEST:", max(results))
