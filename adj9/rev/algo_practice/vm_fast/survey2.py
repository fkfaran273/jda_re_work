import collections, os, pickle, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REV); sys.path.insert(0, HERE)
import vm_final as V
d = pickle.load(open(os.path.join(HERE, "hist_session.pkl"), "rb"))
counts = d["counts"]; pc_of = d["pc_of"]
k_of_pc = {pc: k for k, pc in pc_of.items()}
FAST = V.FAST
GPR = re.compile(r"^[wx]\d+$|^sp$")
def opclass(m, ops):
    parts = [p.strip() for p in ops.split(",")] if ops.strip() else []
    for p in parts:
        p = p.split("[")[0].strip()
        if not p: continue
        if p.startswith("#"): continue
        if not GPR.match(p): return "VEC/OTHER"
    return "GPR"
cl = collections.Counter(); clv = collections.Counter()
VECOPS = collections.Counter()
for k, n in counts.items():
    m, ops, npc = FAST[k]
    c = opclass(m, ops)
    cl[(m, c)] += n
    if c == "VEC/OTHER": clv[m] += n
print("=== executed steps by (mnemonic, operand class) ===")
for (m, c), n in cl.most_common(60):
    print("  %-10s %-10s %12s %5.2f%%" % (m, c, format(n, ","), 100.0*n/sum(counts.values())))
print("\n=== VEC/OTHER steps ===", sum(clv.values()))
for m, n in clv.most_common(30):
    print("   %-10s %12s" % (m, format(n, ",")))
print("\n=== 0x111800-0x112800 disasm sample (hot region) ===")
lo, hi = 0x111800, 0x112800
rows = []
for pc in sorted(k_of_pc):
    if lo <= pc < hi:
        m, ops, npc = FAST[k_of_pc[pc]]
        rows.append((pc, m, ops, counts.get(k_of_pc[pc], 0)))
rows.sort(key=lambda r: -r[3])
for pc, m, ops, n in rows[:20]:
    print("  %08x %-8s %-44s %10s" % (pc, m, ops, format(n, ",")))
print("  ... total ins in window:", len(rows), " steps:", format(sum(r[3] for r in rows), ","))
