import sys, struct, json
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

ops = json.load(open("..\\device\\ops_log.json"))
t = json.load(open("..\\device\\triples_ops.json"))
live_dw = struct.unpack(">44I", bytes.fromhex([x for x in t if x[0] == "blob"][0][2])[16:])

def run(pushkey, popkey):
    ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
    pops = []
    for o in ops:
        tt = o["op"]
        if tt == "PUSH":
            qva = int(o[pushkey], 16) & MASK
            ex.queues.setdefault(qva, []).insert(0, int(o["x2"], 16) & 0xFFFFFFFF)
        elif tt == "POP":
            qva = int(o[popkey], 16) & MASK
            pops.append(ex.queues[qva].pop(0) if ex.queues.get(qva) else 0)
        elif tt == "EMIT":
            s = ex.stream_for(int(o["x1"], 16) & MASK)
            s.emit(int(o["x2"], 16), int(o["x3"], 16), 0x100184)
        elif tt == "LENQ":
            s = ex.stream_for(int(o["x0"], 16) & MASK)
            n = int(o["x1"], 16) & 0xFFFFFFFF
            top = s.data[-1] if s.data else 0
            idx = (top + n) & 0xFFFFFFFF
            v = s.offs[idx] if 0 <= idx < len(s.offs) else (s.data[n] if s.data and 0 <= n < len(s.data) else 0)
            ex.set_reg("w0", v)
    best = (0, None)
    for step in [1, 2, 3]:
        seq = pops[::step]
        for start in range(0, max(1, len(seq) - 44)):
            w = seq[start:start + 44]
            m = sum(1 for a, b in zip(w, live_dw) if (a & 0xFFFFFFFF) == b)
            if m > best[0]:
                best = (m, (step, start))
    return best

for pk in ["x0", "x1"]:
    print("PUSH", pk, run(pk, "x0"))
