import sys, time
sys.path.insert(0, ".")
exec(open("sweep_true.py").read().split("results = []")[0])
t0 = time.time()
ex = build()
print("build %.1f" % (time.time() - t0), flush=True)
ex.__dict__["_heap"] = [0x5A00000000, {}]
ex.__dict__["_truesub"] = True
mains = [va for va, s in ex.streams.items() if len(s.data) > 80]
X26 = 0x5A00002000
ex.mem[X26] = mains[0]
ex.mem[X19LIVE & ~7] = 1
h = wh[1]
ex.R.update({"x0": int(h["x0"], 16) & 0x00FFFFFFFFFFFFFF, "x1": 1,
             "x2": int(h["x2"], 16), "x3": int(h["x3"], 16),
             "x4": int(h["x4"], 16), "x9": int(h["x9"], 16),
             "x19": X19LIVE, "x20": CTXLIVE, "x21": 0, "x23": 0,
             "x26": X26, "x30": 0xDEAD0000, "x29": ex.X29, "sp": INBUF})
ex.pc = 0x12A880
t0 = time.time()
st = ex.run(max_steps=300000)
print("iter1:", st, ex.steps, "t=%.1f" % (time.time() - t0), flush=True)
