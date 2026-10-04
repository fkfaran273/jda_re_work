"""profile_vm.py — classify the ~10M VM steps of one creditsea signing.

Counts steps per instruction index by wrapping the FAST table that
fin_vm2.FinEx.run() reads (`_f = FAST`), then buckets the result by
opcode, by pc range (code region), and by dynamic block.
"""
import collections, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REV)
sys.path.insert(0, os.path.join(REV, "creditsea"))
sys.path.insert(0, HERE)

import fin_vm2, vm_final as V
import testbed as TB
import desc10_58 as LAW

class CountingFAST:
    def __init__(self, fast):
        self.f = fast
        self.c = collections.Counter()
        self.total = 0
    def __getitem__(self, k):
        self.c[k] += 1
        self.total += 1
        return self.f[k]

def run_one(kind="session"):
    s = [x for x in TB.mine_log() if x["val"].get("activity_kind", "session") == kind][0]
    dec = TB.decode(s["blob"])
    d0, d4, d2, pfx = TB.region_parts(dec, s["second"])
    raw, _padded = LAW.claims_for_law_58(s["val"], kind)
    descs = TB.build_descs(s["second"], raw, d0, d4, d2)
    return s, descs

def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else "session"
    s, descs = run_one(kind)
    cf = CountingFAST(V.FAST)
    fin_vm2.FAST = cf          # run() binds `_f = FAST` at entry -> picks this up
    ex = fin_vm2.FinEx(int(s["second"]), descs)
    t0 = time.time()
    status = ex.run(max_steps=60_000_000)
    dt = time.time() - t0
    fin_vm2.FAST = V.FAST
    total = cf.total
    m0 = V.m0
    IDX = V.IDX
    pc_of = {}
    for pc, k in IDX.items():
        pc_of[k] = pc

    by_mnem = collections.Counter()
    for k, n in cf.c.items():
        by_mnem[m0[k]] += n

    # pc-range buckets
    RANGES = [
        (0x100094, 0x12AA48, "serializer/queue-program"),
        (0x99000, 0xBB548, "output-assembly fn (0x99..0xBA)"),
        (0xBB548, 0xBCA30, "tail fn (0xBB..)"),
        (0x146000, 0x149000, "queue-op helpers (0x146..)"),
    ]
    by_range = collections.Counter()
    for k, n in cf.c.items():
        pc = pc_of.get(k, -1)
        for lo, hi, name in RANGES:
            if lo <= pc < hi:
                by_range[name] += n
                break
        else:
            by_range["other"] += n

    print("kind=%s  second=%d  status=%s" % (kind, s["second"], status))
    print("TOTAL steps = %s   wall = %.2f s  (%.2f us/step)"
          % (format(total, ","), dt, dt / max(total, 1) * 1e6))
    print()
    print("=== by pc range ===")
    for name, n in by_range.most_common():
        print("  %-34s %12s  %5.2f%%" % (name, format(n, ","), 100.0 * n / total))
    print()
    print("=== by mnemonic (top 34) ===")
    for name, n in by_mnem.most_common(34):
        print("  %-12s %12s  %5.2f%%" % (name, format(n, ","), 100.0 * n / total))
    print()
    print("distinct instructions executed: %d / %d" % (len(cf.c), len(V.INS)))
    print("emits: %d   nrand: %d" % (len(ex.emit_trace), ex.nrand))
    import pickle
    with open(os.path.join(HERE, "pc_hist_%s.pkl" % kind), "wb") as f:
        pickle.dump({"counts": dict(cf.c), "pc_of": pc_of, "total": total}, f)

if __name__ == "__main__":
    main()
