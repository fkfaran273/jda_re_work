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
xs = [(int(h["x3"], 16) & 0xFFFFFFFF) for h in wh]

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
ex.__dict__["_heap"] = [0x5A00000000, {}]
ex.__dict__["_truesub"] = True
mains = [va for va, s in ex.streams.items() if len(s.data) > 80]
X26 = 0x5A00002000
ex.mem[X26] = mains[0]
ex.mem[X19LIVE & ~7] = 1
OUTBUF = int(wh[0]["x2"], 16) & MASK
ex.R.update({"x21": 0, "x23": 0, "x26": X26})
snapmem = dict(ex.mem)
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
out = b""
for k in range(44):
    a = (OUTBUF + k * 4) & ~7
    w = ex.mem.get(a, 0)
    word = (w & 0xFFFFFFFF) if ((OUTBUF + k * 4) & 7) == 0 else (w >> 32) & 0xFFFFFFFF
    out += struct.pack(">I", word)
m = sum(1 for a, b in zip(out, body_live) if a == b)
print("outbuf bytes", m)
# mem-diff slide: every written run vs blob
written = sorted(a for a in ex.mem if snapmem.get(a) != ex.mem[a])
runs = []
cur = []
for a in written:
    if cur and a == cur[-1] + 8:
        cur.append(a)
    else:
        if len(cur) >= 22:
            runs.append(cur)
        cur = [a]
if len(cur) >= 22:
    runs.append(cur)
print("written runs>=22:", len(runs))
best = (0, None)
for run in runs:
    words = []
    for a in run:
        w = ex.mem.get(a, 0)
        words.append(w & 0xFFFFFFFF)
        words.append((w >> 32) & 0xFFFFFFFF)
    for start in range(0, max(1, len(words) - 44)):
        w44 = words[start:start + 44]
        mm = sum(1 for x, b in zip(w44, live_dw) if (x & 0xFFFFFFFF) == b)
        if mm > best[0]:
            best = (mm, (hex(run[0]), start))
print("best written-run match:", best[0], best[1])
dw = sum(1 for k in range(44) if out[4*k:4*k+4] == body_live[4*k:4*k+4])
print("entries:", len(wh), "bytes", m, "dwords", dw)
print("mine:", out.hex()[:64])
print("live:", body_live.hex()[:64])
# also score every stream tail
best = (0, None)
for va, s in ex.streams.items():
    for name, arr in (("data", s.data), ("offs", s.offs)):
        if len(arr) >= 44:
            for start in [0, max(0, len(arr) - 44)]:
                w = arr[start:start + 44]
                mm = sum(1 for a, b in zip(w, live_dw) if (a & 0xFFFFFFFF) == b)
                if mm > best[0]:
                    best = (mm, (hex(va), name, start))
print("best stream:", best[0], best[1])
