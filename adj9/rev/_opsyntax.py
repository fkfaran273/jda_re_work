"""_opsyntax.py - census of every distinct memory-operand syntax and ALU form
the run actually executes, so the taint parser can mirror them exactly.
"""
import json, re, sys
from collections import Counter
sys.path.insert(0, ".")
import _taint as T
from fin_vm2 import FinEx
from vm_final import INS, IDX

i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
steps = int(sys.argv[2]) if len(sys.argv) > 2 else 11_000_000
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

mn = Counter()
ops = Counter()
seen = set()
orig = tn.hook


def hook(e=None):
    e = e if e is not None else ex
    pc = e.pc
    if pc not in seen:
        seen.add(pc)
        ins = INS[IDX[pc]]
        m = ins.mnemonic
        mn[m] += 1
        ops["%s %s" % (m, ins.op_str)] += 1
    return orig(e)


ex.__dict__["_step_hook"] = hook
st = ex.run(max_steps=steps)
print("status", st, "steps", ex.steps, "distinct pcs", len(seen))
print("--- mnemonics ---")
for k, v in mn.most_common():
    print("  %-8s %d" % (k, v))
print("--- memory-operand syntaxes ---")
for k, v in ops.most_common(400):
    if re.search(r"\[", k):
        print("  %s" % k)
