"""bench.py — time one signing per interpreter, fresh process each rep.

    python bench.py ref|fast|static [kind] [reps]
"""
import hashlib
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
for p in (HERE, REV, os.path.join(REV, "creditsea")):
    if p not in sys.path:
        sys.path.insert(0, p)

SINK = 0x5500000000


def row(kind):
    import testbed as TB
    import desc10_58 as LAW
    s = [x for x in TB.mine_log()
         if x["val"].get("activity_kind", "session") == kind][0]
    dec = TB.decode(s["blob"])
    d0, d4, d2, _p = TB.region_parts(dec, s["second"])
    raw, _pad = LAW.claims_for_law_58(s["val"], kind)
    return s["second"], TB.build_descs(s["second"], raw, d0, d4, d2), s["blob"]


def blob_of(ex):
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    m = bys.get(SINK)
    return b"".join(struct.pack(">I", m.get(k, 0)) for k in range(48))


def main():
    route = sys.argv[1]
    kind = sys.argv[2] if len(sys.argv) > 2 else "session"
    reps = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    second, descs, gold = row(kind)

    if route == "ref":
        import fin_vm2
        cls = fin_vm2.FinEx
        pre = lambda: None
    elif route == "fast":
        import fin_vm2_fast
        cls = fin_vm2_fast.FinEx
        pre = lambda: fin_vm2_fast.prepare()
    elif route == "static":
        import fast_static
        cls = fast_static.FinEx
        pre = lambda: None
    else:
        raise SystemExit("route? ref|fast|static")

    t0 = time.time()
    pre()
    tprep = time.time() - t0

    ts = []
    for _ in range(reps):
        ex = cls(int(second), descs)
        t0 = time.time()
        status = ex.run(max_steps=60_000_000)
        ts.append(time.time() - t0)
    b = blob_of(ex)
    print("%-7s %-11s prep=%.2fs  run=%.3f s  steps=%-9d status=%-11s"
          " gold_exact=%s  sha=%s"
          % (route, kind, tprep, min(ts), ex.steps, status,
             b == gold, hashlib.sha256(b).hexdigest()[:16]))


if __name__ == "__main__":
    main()
