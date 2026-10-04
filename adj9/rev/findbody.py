import sys, struct, json, pickle
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

mem, queues, streams = pickle.load(open("primed.pkl", "rb"))
ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
ex.queues = {k: list(v) for k, v in queues.items()}
for va, (offs, data) in streams.items():
    s = ex.stream_for(va)
    s.offs = list(offs)
    s.data = list(data)
ex.__dict__["_heap"] = [0x5A00000000, {}]
STATE = 0x5A00001000
OUTBUF = 0x5A00002000
MAINSINK = 0x6DFBCE8FA0
X26 = 0x5A00003000
ex.mem[X26] = MAINSINK
X19 = 0x5A00004000
ex.mem[X19] = 1
main = ex.streams[MAINSINK].data
snap0 = {va: (list(s.offs), list(s.data)) for va, s in ex.streams.items()}
snapq0 = {k: list(v) for k, v in ex.queues.items()}
for i in range(44):
    if i == 0:
        x2, x3 = OUTBUF, MAINSINK
    else:
        x2 = 83 + i
        x3 = main[83 + i - 1] if 83 + i - 1 < len(main) else 0
    ex.R.update({"x0": STATE, "x1": i, "x2": x2, "x3": x3,
                 "x4": 0x10, "x9": 0x5A, "x19": X19, "x20": 0,
                 "x21": 0, "x23": 0, "x26": X26, "x30": 0xDEAD0000,
                 "x29": ex.X29, "sp": MAINSINK})
    ex.pc = 0x12A880
    ex.run(max_steps=200000)
    ex.__dict__["_shadow"] = []
t = json.load(open("..\\device\\triples_ops.json"))
body_live = bytes.fromhex([x for x in t if x[0] == "blob"][0][2])[16:]
best = (0, None, None)
for va, s in ex.streams.items():
    o0, d0 = snap0.get(va, ([], []))
    for name, old, new in (("data", d0, s.data), ("offs", o0, s.offs)):
        if len(new) > len(old):
            tail = new[len(old):]
            if len(tail) >= 40:
                tb = b"".join(struct.pack(">I", v) for v in tail[:44])
                m = sum(1 for a, b in zip(tb, body_live) if a == b)
                if m > best[0]:
                    best = (m, va, name)
print("best stream-tail match:", best[0], "/176", hex(best[1]) if best[1] else None, best[2])
for k, v in ex.queues.items():
    old = snapq0.get(k, [])
    if len(v) != len(old):
        print("queue", hex(k), len(old), "->", len(v))
memdiff = [(a, v) for a, v in ex.mem.items() if v != 0]
print("nonzero mem words:", len(memdiff))
