import sys, struct, json, glob
sys.path.insert(0, ".")
from vm_final import Ex
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

def apply_op(ex, o):
    t = o["op"]
    R = ex.R
    if t == "PUSH":
        qva = int(o["x1"], 16) & MASK
        ex.queues.setdefault(qva, []).insert(0, int(o["x2"], 16) & 0xFFFFFFFF)
    elif t == "POP":
        qva = int(o["x0"], 16) & MASK
        if ex.queues.get(qva):
            R["w0"] = ex.queues[qva].pop(0)
            R["x0"] = R["w0"]
        else:
            R["w0"] = 0
            R["x0"] = 0
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

if __name__ == "__main__":
    ops = json.load(open("..\\device\\ops_log.json"))
    ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
    for path in sorted(glob.glob("..\\device\\vm_mem\\R_*.bin")):
        base = int(path.split("R_")[1].split(".bin")[0], 16)
        data = open(path, "rb").read()
        for off in range(0, len(data) - 7, 8):
            v = struct.unpack("<Q", data[off:off + 8])[0]
            if v:
                ex.mem[base + off] = untag(v)
    for o in ops:
        if o["op"] in ("PUSH", "POP", "EMIT", "LENQ"):
            apply_op(ex, o)
    from collections import Counter
    print("streams:", len(ex.streams), "queues:", len(ex.queues))
    for va, s in list(ex.streams.items())[:8]:
        print(hex(va), "data:", len(s.data), "offs:", len(s.offs))
    import pickle
    pickle.dump((dict(ex.mem), ex.queues,
                 {k: (s.offs, s.data) for k, s in ex.streams.items()}),
                open("primed.pkl", "wb"))
    print("primed saved")
