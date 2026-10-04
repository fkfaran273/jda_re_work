import sys, struct, json, pickle
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

ops = json.load(open("..\\device\\ops_log.json"))
ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
for path in ["..\\device\\vm_mem\\R_6e629fb000.bin",
             "..\\device\\vm_mem\\R_6e72a60000.bin",
             "..\\device\\vm_mem\\R_6ed2adc000.bin"]:
    import glob as _g
    for p in _g.glob(path):
        base = int(p.split("R_")[1].split(".bin")[0], 16)
        data = open(p, "rb").read()
        for off in range(0, len(data) - 7, 8):
            v = struct.unpack("<Q", data[off:off + 8])[0]
            if v:
                ex.mem[base + off] = untag(v)
pops = []
for o in ops:
    t = o["op"]
    if t == "PUSH":
        qva = int(o["x1"], 16) & MASK
        ex.queues.setdefault(qva, []).insert(0, int(o["x2"], 16) & 0xFFFFFFFF)
    elif t == "POP":
        qva = int(o["x0"], 16) & MASK
        if ex.queues.get(qva):
            pops.append(ex.queues[qva].pop(0))
        else:
            pops.append(0)
    elif t == "EMIT":
        s = ex.stream_for(int(o["x1"], 16) & MASK)
        s.emit(int(o["x2"], 16), int(o["x3"], 16), 0x100184)
    elif t == "LENQ":
        s = ex.stream_for(int(o["x0"], 16) & MASK)
        n = int(o["x1"], 16) & 0xFFFFFFFF
        top = s.data[-1] if s.data else 0
        idx = (top + n) & 0xFFFFFFFF
        if 0 <= idx < len(s.offs):
            v = s.offs[idx]
        elif s.data and 0 <= n < len(s.data):
            v = s.data[n]
        else:
            v = 0
        ex.set_reg("w0", v)
print("pops:", len(pops))
t = json.load(open("..\\device\\triples_ops.json"))
body_live = bytes.fromhex([x for x in t if x[0] == "blob"][0][2])[16:]
live_dw = struct.unpack(">44I", body_live)
# slide: every window of 44 pops (step 1) + every-k subsamples
best = (0, None)
for step in [1, 2, 3]:
    seq = pops[::step]
    for start in range(0, max(1, len(seq) - 44)):
        w = seq[start:start + 44]
        m = sum(1 for a, b in zip(w, live_dw) if (a & 0xFFFFFFFF) == b)
        if m > best[0]:
            best = (m, (step, start))
print("best pop-window match:", best[0], "/44", best[1])
# also try BE/LE + rev variants on best window
if best[1]:
    step, start = best[1]
    w = pops[::step][start:start + 44]
    import struct as _s
    for name, conv in [("raw", lambda v: v & 0xFFFFFFFF),
                       ("rev", lambda v: _s.unpack(">I", _s.pack("<I", v & 0xFFFFFFFF))[0]),
                       ("not", lambda v: (~v) & 0xFFFFFFFF)]:
        cw = [conv(v) for v in w]
        m = sum(1 for a, b in zip(cw, live_dw) if a == b)
        print(name, m)
