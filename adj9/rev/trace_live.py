import sys, struct
sys.path.insert(0, ".")
from vm_final import Ex
DD = "..\\device\\memdump\\"
def untag(v):
    return v & 0x00FFFFFFFFFFFFFF if (v >> 56) == 0xB4 else v
def stock(ex, path, base):
    d = open(path, "rb").read()
    for off in range(0, len(d) - 7, 8):
        v = struct.unpack("<Q", d[off:off + 8])[0]
        if v:
            ex.mem[base + off] = untag(v)
def fresh():
    ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
    ex.R.update({"x0": 0x6DA042D170, "x1": 0x6F02A1E430, "x2": 0x6DA042D800,
                 "x3": 0x6DA11D8EB8, "x4": 0x6DA042D0A0,
                 "x9": 0x558C387EB58ADBA, "x19": 0x6DA042D0B0,
                 "x30": 0xDEAD0000, "x29": ex.X29, "sp": 0x6DA042D090})
    stock(ex, DD + "x0_6da042d170.bin", 0x6DA042D170 - 0x10000)
    stock(ex, DD + "x1_6f02a1e430.bin", 0x6F02A19000)
    stock(ex, DD + "x3_6da11d8eb8.bin", 0x6DA11D8000)
    stock(ex, DD + "sp_6da042d090.bin", 0x6DA042D090 - 0x10000)
    ex.pc = 0xBB548
    return ex
if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 320
    ex = fresh()
    st = ex.run(max_steps=n)
    print(st, ex.steps, "pc", hex(ex.pc))
    print("x8", hex(ex.R.get("x8", 0)), "x9", hex(ex.R.get("x9", 0)),
          "x19", hex(ex.R.get("x19", 0)))
    print("hub", [hex(v) for v in ex.__dict__.get("_hublog", [])])
    print("roll", [hex(v) for v in ex.__dict__.get("_roll", [])][-16:])
