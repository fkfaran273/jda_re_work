import sys, struct, json
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

ops = json.load(open("..\\device\\ops_log.json"))
ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
ex.__dict__["_truesub"] = True
lenqs = []
for idx, o in enumerate(ops):
    t = o["op"]
    pc = 0x100184 if idx < 183 else 0
    if t == "PUSH":
        qva = int(o["x1"], 16) & MASK
        ex.queues.setdefault(qva, []).insert(0, int(o["x2"], 16) & 0xFFFFFFFF)
    elif t == "POP":
        qva = int(o["x0"], 16) & MASK
        if ex.queues.get(qva):
            ex.queues[qva].pop(0)
    elif t == "EMIT":
        s = ex.stream_for(int(o["x1"], 16) & MASK)
        s.emit(int(o["x2"], 16), int(o["x3"], 16), pc)
    elif t == "LENQ":
        ex.R.update({"x0": int(o["x0"], 16) & MASK,
                     "x1": int(o["x1"], 16)})
        ex.__dict__.setdefault("_shadow", []).append(0xDEAD0001)
        ex.pc = 0x147304
        ex.run(max_steps=20000)
        v = ex.R.get("w0", 0)
        if idx >= 183:
            lenqs.append(v)
print("workhorse LENQs:", len(lenqs))
print([hex(v) for v in lenqs[:10]])
t = json.load(open("..\\device\\triples_ops.json"))
for bi, tag in [([x for x in t if x[0] == "blob"][0], "sess"),
                ([x for x in t if x[0] == "blob"][1], "click")]:
    live_dw = struct.unpack(">44I", bytes.fromhex(bi[2])[16:])
    best = (0, None)
    for start in range(0, max(1, len(lenqs) - 44)):
        w = lenqs[start:start + 44]
        m = sum(1 for a, b in zip(w, live_dw) if (a & 0xFFFFFFFF) == b)
        if m > best[0]:
            best = (m, start)
    print(tag, "best:", best[0], best[1])
