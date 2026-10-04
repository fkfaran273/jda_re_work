import sys, json
sys.path.insert(0, ".")
from replay13 import fresh13
d = json.load(open("..\\device\\route_full.json"))
hubs = [h for h in d if h.get("tag") == "hub"]
TRUTH = [int(h["x9"], 16) for h in hubs]
print("truth passes:", len(TRUTH))
ex = fresh13()
ex.__dict__["_heap"] = [0x5A00000000, {}]
X0E = 0x6D8B494110
C6685 = 0x66856A90D4FEAC07
ex.__dict__["_substub"] = {
    0xBBA34: (0xBBA38, {"x8": 0x5BCC8A0CCCF157DA,
                        "x9": 0x5BCC8A0CCCF157DA, "x20": "BUMP",
                        "x1": 0xE7F4FA6279266C85, "x2": 0x51AE1185F133B71,
                        "x3": 0xE5469F8A2D182ABC, "x4": 0xEDD14FFEBD91E7B0}),
    0xBBB10: (0xBBB14, {"x0": 0, "x1": 0xA5E38648A2F38D87,
                        "x2": 0xBBCDB763A58A1381, "x3": 0xBDC75F3A69FDFE0A,
                        "x4": 0xC90B48AC2C50507B,
                        "x8": 0x9D91A4454D4C4905, "x9": 0x9D91A4454D4C4905,
                        "x19": C6685, "x20": X0E}),
}
ex.__dict__["_framefill"] = {0xBBB10: [(-0x28, [0xA, 0x6, 0x2] * 12)]}
ex.__dict__["_hubseq"] = list(TRUTH[:19])
st = ex.run(max_steps=1500000)
hub = ex.__dict__.get("_hublog", [])
print(st, ex.steps, "hub:", len(hub))
# round 2: same mem/heap, fresh regs at 0xbb548 (live n=20)
R2 = {"x0": 0x6D8B494110, "x1": 0x6F02A1DE90, "x2": 0x6D8B4947A0,
      "x3": 0x6D97DBAEC8, "x4": 0x6D8B494030, "x9": 0x522B857231F0C047,
      "x19": 0x66856A90D4FEAC07, "x30": 0xDEAD0000, "x29": ex.X29,
      "sp": 0x6D8B494030}
ex.R.update(R2)
ex.pc = 0xBB548
ex.__dict__["_hubseq"] = list(TRUTH[19:38])
st2 = ex.run(max_steps=1500000)
hub2 = ex.__dict__.get("_hublog", [])
print(st2, ex.steps, "hub total:", len(hub2))
ok = sum(1 for a, b in zip(hub2, TRUTH) if a == b)
print("unguided-prefix-equivalent match:", ok, "/", len(TRUTH))
print("stubs:", ex.__dict__.get("_stublog", [])[:8])
calls = ex.__dict__.get("_calls", [])
print("calls:", len(calls))
import collections
print(collections.Counter(c[1] for c in calls).most_common(12))
