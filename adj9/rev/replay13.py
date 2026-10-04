import sys, struct, json, glob, os
sys.path.insert(0, ".")
from vm_final import Ex
DD = "..\\device\\memdump4\\"
META = json.load(open(DD + "meta.json"))
REGS = {k: int(v, 16) for k, v in META["regs"].items() if v.startswith("0x")}
MASK = 0x00FFFFFFFFFFFFFF

def untag(v):
    return v & MASK if (v >> 56) == 0xB4 else v

def file_base(path, vas):
    d = open(path, "rb").read()
    best = None
    for va in vas:
        o = d.find(struct.pack("<Q", va))
        if o >= 0:
            base = va - o
            best = base
            break
        o = d.find(struct.pack("<Q", va | 0xB400000000000000))
        if o >= 0:
            best = va - o
            break
    return best

def stock_all(ex):
    vas = [v & MASK for v in REGS.values() if v > 0x10000]
    n = 0
    for path in sorted(glob.glob(DD + "*.bin")):
        base = file_base(path, vas)
        if base is None:
            continue
        d = open(path, "rb").read()
        for off in range(0, len(d) - 7, 8):
            v = struct.unpack("<Q", d[off:off + 8])[0]
            if v:
                ex.mem[base + off] = untag(v)
                n += 1
    return n

def fresh13():
    ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
    ex.R.update({"x0": REGS["x0"], "x1": REGS["x1"] & MASK,
                 "x2": REGS["x2"], "x3": REGS["x3"], "x4": REGS["x4"],
                 "x9": REGS["x9"], "x19": REGS["x19"], "x30": 0xDEAD0000,
                 "x29": ex.X29, "sp": REGS["sp"]})
    n = stock_all(ex)
    ex.mem[REGS["x0"] & ~7] = 0  # level-cell[0] is 0 live
    print("stocked", n)
    ex.pc = 0xBB548
    return ex

if __name__ == "__main__":
    ex = fresh13()
    print("entry ok")
