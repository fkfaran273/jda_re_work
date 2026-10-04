"""_taintdbg.py - where does the taint chain break?  Counts, per step class:
  * mem reads/writes that touch a descriptor window
  * registers whose taint becomes non-zero
  * the max popcount ever seen
Prints the first few descriptor-window accesses and the last sink state.
"""
import json, struct, sys, time
sys.path.insert(0, ".")
import _taint as T
from fin_vm2 import FinEx

i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
steps = int(sys.argv[2]) if len(sys.argv) > 2 else 2_000_000
rows = json.load(open("all_signings.json"))
ph3 = json.load(open("pair_h3.json"))
d = T.descs_of(rows[i])
ex = FinEx(ph3[i]["second"], d)
nd = []
for lendl, tag, data in d:
    raw = bytes(data)
    padded = raw + b"\x00" * (-len(raw) % 4)
    nd.append((max(int(lendl), len(padded) // 4), tag, padded))
tn = T.Taint(ex, nd)

DBASE, DST = T.DESC_BASE, T.DESC_STRIDE
stat = {"desc_read": 0, "desc_read_nz": 0, "reg_nz": 0, "maxpc": 0, "emits": 0}
first = []
orig_apply = tn._apply


def apply(p):
    kind, extra, dests, srcs, snap = p
    for op in snap:
        if op[0] in ("load", "load2") and isinstance(op[1], int):
            a = op[1]
            if DBASE <= a < DBASE + 11 * DST:
                stat["desc_read"] += 1
                v = tn.mem.get(a, 0)
                if v:
                    stat["desc_read_nz"] += 1
                    if len(first) < 12:
                        first.append((ex.steps, hex(a), (a - DBASE) // DST,
                                      (a - DBASE) % DST // 4, hex(v)))
        if op[0] == "emit":
            stat["emits"] += 1
    orig_apply(p)
    for c, m in tn.R.items():
        if m:
            stat["reg_nz"] += 1
            b = bin(m).count("1")
            if b > stat["maxpc"]:
                stat["maxpc"] = b
    return None


tn._apply = apply
ex.__dict__["_step_hook"] = tn.hook
st = ex.run(max_steps=steps)
print("status", st, "steps", ex.steps, stat)
print("first descriptor reads (step, addr, desc, word, mask):")
for f in first:
    print("  ", f)
print("sink taint per word:", [bin(tn.sink_mask(k)).count("1") for k in range(48)])
print("nonzero reg taint slots:", {c: hex(m) for c, m in list(tn.R.items())[:20] if m})
