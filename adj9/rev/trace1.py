import sys
sys.path.insert(0, ".")
exec(open("sweep2.py").read().split("if __name__")[0])
ex = build()
ex.__dict__["_heap"] = [0x5A00000000, {}]
ex.__dict__["_truesub"] = True
mains = [va for va, s in ex.streams.items() if len(s.data) > 80]
X26 = 0x5A00002000
ex.mem[X26] = mains[0]
ex.mem[X19LIVE & ~7] = 1
# full trace: wrap mem_op reads? simpler: log _calls + _slog + qlog already; add read addrs via ld hook
reads = []
_orig_ld = Ex.ld
def traced_ld(self, va, size=8):
    if 0x12A880 <= self.pc <= 0x12C000 or 0x146000 <= self.pc <= 0x149000:
        reads.append((hex(self.pc), hex(va), size))
    return _orig_ld(self, va, size)
Ex.ld = traced_ld
h = [x for x in wh if int(x["x1"], 16) == 1][0]
ex.R.update({"x0": int(h["x0"], 16) & MASK, "x1": 1,
             "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
             "x4": int(h["x4"], 16), "x9": int(h["x9"], 16),
             "x19": X19LIVE, "x20": CTXLIVE, "x21": 0, "x23": 0,
             "x26": X26, "x30": 0xDEAD0000, "x29": ex.X29, "sp": INBUF})
ex.pc = 0x12A880
st = ex.run(max_steps=20000)
print(st, ex.steps)
print("reads:", len(reads))
for r in reads[:40]:
    print(r)
print("calls:", [(c[0], c[1]) for c in ex.__dict__.get("_calls", [])][:12])
