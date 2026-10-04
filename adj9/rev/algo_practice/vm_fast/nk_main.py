"""nk_main.py — Nuitka/Cython entry point: mint one creditsea gold blob with
the static block table and print time + sha256 of the 192-B result."""
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))
for p in (HERE, REV, os.path.join(REV, "creditsea")):
    if p not in sys.path:
        sys.path.insert(0, p)

import struct
import testbed as TB
import desc10_58 as LAW
import fast_static

SINK = TB.SINK


def mint(second, descs):
    ex = fast_static.FinEx(int(second), descs)
    status = ex.run(max_steps=60_000_000)
    last = {}
    for (sva, n, v) in ex.emit_trace:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    bys = {}
    for ((sva, n), v) in last.items():
        bys.setdefault(sva, {})[n] = v
    m = bys.get(SINK)
    blob = b"".join(struct.pack(">I", m.get(k, 0)) for k in range(48))
    return blob, status, ex.steps


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else "session"
    s = [x for x in TB.mine_log()
         if x["val"].get("activity_kind", "session") == kind][0]
    dec = TB.decode(s["blob"])
    d0, d4, d2, _p = TB.region_parts(dec, s["second"])
    raw, _pad = LAW.claims_for_law_58(s["val"], kind)
    descs = TB.build_descs(s["second"], raw, d0, d4, d2)
    t0 = time.time()
    blob, status, steps = mint(s["second"], descs)
    dt = time.time() - t0
    gold = bytes.fromhex([g for g in LAW.GOLD if g["kind"] == kind][0]["blob_hex"])
    print("kind=%s second=%d status=%s steps=%d" % (kind, s["second"], status, steps))
    print("sha256=%s" % hashlib.sha256(blob).hexdigest())
    print("GOLD-EXACT=%s" % (blob == gold))
    print("time=%.3f s" % dt)


if __name__ == "__main__":
    main()
