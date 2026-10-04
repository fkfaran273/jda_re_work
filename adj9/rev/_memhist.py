"""_memhist.py - which addresses does the program actually read?  Histogram of
load addresses, plus a dump of instructions whose memory operand my parser
fails on, so the taint parser can be completed.
"""
import json, re, sys
from collections import Counter
sys.path.insert(0, ".")
import _taint as T
from fin_vm2 import FinEx
from vm_final import INS, IDX

i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
steps = int(sys.argv[2]) if len(sys.argv) > 2 else 3_000_000
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

addrs = Counter()
unparsed = Counter()
pcset = set()
orig = tn.hook


def hook(e=None):
    e = e if e is not None else ex
    pc = e.pc
    if pc not in pcset:
        pcset.add(pc)
        ins = INS[IDX[pc]]
        kind, extra, dests, srcs, _ = T.parse(pc)
        if ins.mnemonic in ("ldr", "ldur", "str", "stur", "ldrb", "strb",
                            "ldrsh", "ldrh", "ldrsb", "ldrsw", "ldursw",
                            "ldp", "stp", "ldpsw") and extra is None:
            unparsed["%s %s" % (ins.mnemonic, ins.op_str)] += 1
    return orig(e)


ex.__dict__["_step_hook"] = hook
st = ex.run(max_steps=steps)
print("status", st, "steps", ex.steps, "distinct pcs", len(pcset))
print("UNPARSED mem operands:")
for k, v in unparsed.most_common(30):
    print("  %5d  %s" % (v, k))
