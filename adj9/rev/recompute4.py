import sys, struct, json, pickle
sys.path.insert(0, ".")
from vm_final import Ex

mem, queues, streams = pickle.load(open("primed.pkl", "rb"))
ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
ex.queues = queues
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
for i in range(44):
    if i == 0:
        x2, x3 = OUTBUF, MAINSINK
    else:
        s = ex.streams[MAINSINK]
        x2 = 83 + i
        x3 = s.data[83 + i - 1] if 83 + i - 1 < len(s.data) else 0
    ex.R.update({"x0": STATE, "x1": i, "x2": x2, "x3": x3,
                 "x4": 0x10, "x9": 0x5A, "x19": X19, "x20": 0,
                 "x21": 0, "x23": 0, "x26": X26, "x30": 0xDEAD0000,
                 "x29": ex.X29, "sp": MAINSINK})
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
open("body_v4.bin", "wb").write(out)
print("body:", out.hex()[:64])
print("nonzero:", sum(1 for k in range(44) if int.from_bytes(out[4*k:4*k+4], "big") != 0))
for va, s in sorted(ex.streams.items()):
    if len(s.data) > 130 or len(s.offs) > 5:
        print(hex(va), "data:", len(s.data), "offs:", len(s.offs))
