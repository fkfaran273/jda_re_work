import sys, struct, json
sys.path.insert(0, ".")
from vm_final import Ex

DD = "..\\device\\memdump\\"
TRUTH = [0x522B857231F0C047, 0x66856A90D4FEAC07, 0x66856A90D4FEAC07,
         0xE64650C616CDA5CE, 0x5F69F144A4A7722A, 0x41DC46B67C5BF6,
         0xF00481F4AFA5CE68, 0x525E0726F260147E, 0xF00481F4AFA5CE68,
         0x525E0726F260147E, 0xF00481F4AFA5CE68, 0x967FC24C2731E221]

def untag(v):
    return v & 0x00FFFFFFFFFFFFFF if (v >> 56) == 0xB4 else v

def stock(ex, path, base):
    d = open(path, "rb").read()
    for off in range(0, len(d) - 7, 8):
        v = struct.unpack("<Q", d[off:off + 8])[0]
        if v:
            ex.mem[base + off] = untag(v)

ex = Ex(seed=1, descs=[(0, 0, b"")], shared_q=True)
R = {"x0": 0x6DA042D170, "x1": 0x6F02A1E430, "x2": 0x6DA042D800,
     "x3": 0x6DA11D8EB8, "x4": 0x6DA042D0A0, "x9": 0x558C387EB58ADBA,
     "x19": 0x6DA042D0B0, "x30": 0xDEAD0000}
ex.R.update(R)
ex.R["x29"] = ex.X29
stock(ex, DD + "x0_6da042d170.bin", 0x6DA042D170 - 0x10000)
stock(ex, DD + "x1_6f02a1e430.bin", 0x6F02A19000)
stock(ex, DD + "x3_6da11d8eb8.bin", 0x6DA11D8000)
stock(ex, DD + "sp_6da042d090.bin", 0x6DA042D090 - 0x10000)
# entry stack pointer -> real sp value (stock sp file separately is wrong:
# sp points into heap window already stocked above; set R sp):
ex.R["sp"] = 0x6DA042D090
ex.pc = 0xBB548
st = ex.run(max_steps=400000)
hub = ex.__dict__.get("_hublog", [])
print(st, ex.steps, "hub passes:", len(hub))
ok = 0
for i, (got, want) in enumerate(zip(hub, TRUTH)):
    mark = "OK " if got == want else "DIVERGE"
    if got == want:
        ok += 1
    else:
        print(i, mark, "got", hex(got), "want", hex(want))
        break
print("prefix match:", ok, "/", len(TRUTH))
calls = ex.__dict__.get("_calls", [])
print("calls:", len(calls))
for c in calls[:15]:
    print("  ", c[0], c[1], ["%x" % x for x in c[2]][:4])
