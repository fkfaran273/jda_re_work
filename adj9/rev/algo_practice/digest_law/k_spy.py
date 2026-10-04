"""k_spy.py — full-run light spy: find every queue-op touching the 8 K words
(KPAD_IN = the digest HMAC key) and every EMIT of them, over the whole run."""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AP = os.path.dirname(HERE)
REV = os.path.dirname(AP)
sys.path.insert(0, REV)
sys.path.insert(0, REV)
sys.path.insert(0, AP)

import fin_vm2
from fin_vm2 import FinEx
import vm_final as V
from vm_final import IDX
from dump_streams import build_descs, SEC

KWORDS = [0x690f6094, 0x4dddd984, 0x7db55cd7, 0xd2d576b3,
          0x0451723f, 0xbcfa92df, 0x62b55f6f, 0xec60f2de]
KSET = set(KWORDS)

BL_PUSH, BL_POP = 0x147630, 0x147734
BL_EMIT, BL_LENQ = 0x146ed8, 0x147304
BL_SWAP, BL_CAPP = 0x147a20, 0x14784c
BL_CAPP0 = 0x147a18


def main():
    hits = []
    hits_append = hits.append

    def hook(e):
        pc = e.pc
        k = IDX.get(pc)
        if k is None:
            return
        mnem, ops = V.FAST[k][0], V.FAST[k][1]
        if mnem != "bl":
            return
        t = V.pt(ops)
        if t in (BL_PUSH, BL_POP, BL_EMIT, BL_LENQ, BL_SWAP, BL_CAPP, BL_CAPP0):
            for r in ("w3", "w0", "w2"):
                v = e.R.get(r, 0) & 0xFFFFFFFF
                if v in KSET:
                    hits_append((e.steps, pc, t, r, v))
                    break

    descs = build_descs()
    ex = FinEx(SEC, descs)
    ex.__dict__['_step_hook'] = hook
    t0 = time.time()
    status = ex.run(max_steps=60_000_000)
    print("status=%s steps=%d hits=%d (%.1fs)" % (status, ex.steps, len(hits), time.time() - t0))
    for h in hits[:80]:
        print(h)
    json.dump(hits, open(os.path.join(HERE, "k_spy_hits.json"), "w"))


if __name__ == "__main__":
    main()
