"""profile2.py — deeper classification: hot pcs, bl-target histogram, and
phase segmentation by pc window."""
import collections, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REV); sys.path.insert(0, os.path.join(REV, "creditsea")); sys.path.insert(0, HERE)
import fin_vm2, vm_final as V, testbed as TB, desc10_58 as LAW
from profile_vm import CountingFAST, run_one

class BlCount:
    def __init__(self, fast, pc_of):
        self.f = fast; self.c = collections.Counter(); self.pc_of = pc_of; self.bl_pc = collections.Counter()
    def __getitem__(self, k):
        self.c[k] += 1
        m, ops, npc = self.f[k]
        if m == "bl":
            self.bl_pc[k] += 1
        return (m, ops, npc)

def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else "session"
    s, descs = run_one(kind)
    pc_of = {k: pc for pc, k in V.IDX.items()}
    cf = BlCount(V.FAST, pc_of)
    fin_vm2.FAST = cf
    ex = fin_vm2.FinEx(int(s["second"]), descs)
    t0 = time.time(); status = ex.run(max_steps=60_000_000); dt = time.time() - t0
    fin_vm2.FAST = V.FAST
    total = sum(cf.c.values())
    pts = V.pt
    print("total=%s  %.2fs" % (format(total, ","), dt))

    # bl target histogram
    tgt = collections.Counter()
    NAMES = {0x147630: "PUSH", 0x147734: "POP", 0x146470: "PUSH2", 0x146478: "POP2",
             0x146ed8: "EMIT", 0x147304: "LENQ", 0x1472e8: "OUTLEN",
             0x147120: "PUSHS", 0x147220: "POPS", 0x146558: "MKITER",
             0x146650: "ITERNEXT", 0x148d10: "RAND", 0x146474: "ISEMPTY",
             0x147a20: "CAP_SWAP", 0x14784c: "CAP_PUSH", 0x147a18: "CAP_PUSH0",
             0x148B10: "malloc", 0x148B90: "calloc", 0x148BA0: "memcpy",
             0x148A20: "memset", 0x148C80: "realloc", 0x148CE0: "strlen"}
    for k, n in cf.bl_pc.items():
        t = pts(V.FAST[k][1])
        tgt[t] += n
    print("\n=== bl targets (semantic ops) ===")
    for t, n in tgt.most_common(30):
        print("  %-10s %s  %12s  %5.2f%%" % (NAMES.get(t, ""), hex(t or 0), format(n, ","), 100.0*n/total))
    print("  bl total %s (%.2f%%)" % (format(sum(cf.bl_pc.values()), ","), 100.0*sum(cf.bl_pc.values())/total))

    # top hot pcs
    print("\n=== top 30 hot pcs ===")
    for k, n in cf.c.most_common(30):
        pc = pc_of.get(k, -1)
        m, ops, npc = V.FAST[k]
        print("  %08x  %-8s %-40s %10s  %5.2f%%" % (pc, m, ops[:40], format(n, ","), 100.0*n/total))

    # 4KB window histogram of the program region
    print("\n=== steps by 0x400 pc window (top 22) ===")
    win = collections.Counter()
    for k, n in cf.c.items():
        win[(pc_of.get(k, -1) >> 10) << 10] += n
    for pc, n in win.most_common(22):
        print("  %08x-%08x  %12s  %5.2f%%" % (pc, pc+0x400, format(n, ","), 100.0*n/total))
    import pickle
    pickle.dump({"counts": dict(cf.c), "pc_of": pc_of}, open(os.path.join(HERE, "hist_%s.pkl" % kind), "wb"))

if __name__ == "__main__":
    main()
