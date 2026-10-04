import sys
sys.path.insert(0, ".")
from trace_live import fresh
TRUTH = [0x522B857231F0C047, 0x66856A90D4FEAC07, 0x66856A90D4FEAC07,
         0xE64650C616CDA5CE, 0x5F69F144A4A7722A, 0x41DC46B67C5BF6,
         0xF00481F4AFA5CE68, 0x525E0726F260147E, 0xF00481F4AFA5CE68,
         0x525E0726F260147E, 0xF00481F4AFA5CE68, 0x967FC24C2731E221]
CANDS = [0x1, 0x6F02A1E430, 0xB400006F02A1E430, 0x6DA042D834, 0x6DA042D800,
         0x6DD7F3B9BC, 0x100, 0x6DA042D170]
for v in CANDS:
    ex = fresh()
    ex.__dict__["_blrret"] = {0xBABF4: v}
    st = ex.run(max_steps=120000)
    hub = ex.__dict__.get("_hublog", [])
    ok = sum(1 for a, b in zip(hub, TRUTH) if a == b)
    print(hex(v), st, ex.steps, "hub:", len(hub), "match:", ok)
