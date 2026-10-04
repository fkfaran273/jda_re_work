import sys
sys.path.insert(0, ".")
from trace_live import fresh
# session-5 full hub x9 truth (route5.json)
TRUTH = [0x522B857231F0C047, 0x66856A90D4FEAC07, 0xE64650C616CDA5CE,
         0x5F69F144A4A7722A, 0x41DC46B67C5BF6, 0xF00481F4AFA5CE68,
         0x525E0726F260147E, 0xF00481F4AFA5CE68, 0x525E0726F260147E,
         0xF00481F4AFA5CE68, 0x967FC24C2731E221, 0x79A4322A41567E9E,
         0x81442432BA1B7D12, 0xBBDDA18F0E7D052A, 0xEB88DFF40AA29136,
         0x61053514467EA5AE, 0x445B17F0CB37DB37, 0xC4CF4917D93D24CA,
         0xF88BCDB2D3F53831]
ex = fresh()
ex.mem[0x6DA042D170 & ~7] = 0  # level-cell[0] is 0 live (slice 75)
ex.__dict__["_heap"] = [0x5A00000000, {}]
X0E = 0x6DA042D170
C6685 = 0x66856A90D4FEAC07
ex.__dict__["_substub"] = {
    0xBBA34: (0xBBA38, {"x8": 0x5BCC8A0CCCF157DA,
                        "x9": 0x5BCC8A0CCCF157DA, "x20": "BUMP",
                        "x1": 0xE7F4FA6279266C85, "x2": 0x51AE1185F133B71,
                        "x3": 0xE5469F8A2D182ABC, "x4": 0xEDD14FFEBD91E7B0}),
    # 0x9c478 full live contract (slice 75): skip interior, apply regs+fills
    0xBBB10: (0xBBB14, {"x0": 0, "x1": 0xA5E38648A2F38D87,
                        "x2": 0xBBCDB763A58A1381, "x3": 0xBDC75F3A69FDFE0A,
                        "x4": 0xC90B48AC2C50507B,
                        "x8": 0x9D91A4454D4C4905, "x9": 0x9D91A4454D4C4905,
                        "x19": 0x66856A90D4FEAC07, "x20": X0E}),
}
ex.__dict__["_framefill"] = {0xBBB10: [(-0x28, 0xA)]}
st = ex.run(max_steps=600000)
hub = ex.__dict__.get("_hublog", [])
print(st, ex.steps, "hub:", len(hub))
ok = 0
for i, (got, want) in enumerate(zip(hub, TRUTH)):
    if got != want:
        print("DIVERGE at", i, "got", hex(got), "want", hex(want))
        break
    ok += 1
print("prefix:", ok, "/", len(TRUTH))
print("stubs:", ex.__dict__.get("_stublog", []))
calls = ex.__dict__.get("_calls", [])
print("calls:", len(calls))
for c in calls[:20]:
    print("  ", c[0], c[1], ["%x" % x for x in c[2]][:5])
