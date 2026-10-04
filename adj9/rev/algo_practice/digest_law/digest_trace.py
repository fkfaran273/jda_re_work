"""digest_trace.py — provenance for digest words 40..47 (blob[160:192)).

pass 1: FinStream.emit spy with VM step numbers -> map the digest-relevant
        EMITs (KPAD_IN, HASH_IN, hashB, hashA, digest) to steps and find the
        step window of the digest machinery.
pass 2 (--pass2): windowed per-step hook over the digest window: every
        register change, every store, every queue op (PUSH/POP/LENQ/EMIT...).

Usage:
    python digest_trace.py            # pass 1 (fast)
    python digest_trace.py --pass2 LO HI   # windowed provenance [LO,HI] steps
"""
import inspect
import json
import os
import struct
import sys
import textwrap
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AP = os.path.dirname(HERE)
REV = os.path.dirname(AP)
sys.path.insert(0, REV)
sys.path.insert(0, REV)
sys.path.insert(0, AP)

import fin_vm2
from fin_vm2 import FinEx, FinStream
import vm_final as V
from dump_streams import build_descs, SEC

MAIN = 0x5450001000
SINK = 0x5500000000

# ---------------------------------------------------------------- pass 1
EMITS = []
_OWNER = {}
_orig_emit = FinStream.emit


def emit_spy(self, n, v):
    n &= 0xFFFFFFFF
    v &= 0xFFFFFFFF
    top = self.top[-1]
    _orig_emit(self, n, v)
    ex = _OWNER.get(self.va)
    EMITS.append(((ex.steps if ex else -1), self.va, top, n, v, top + n))


def pass1():
    FinStream.emit = emit_spy
    descs = build_descs()
    ex = FinEx(SEC, descs)
    _OWNER.update({sva: ex for sva in ex.streams})
    t0 = time.time()
    status = ex.run(max_steps=60_000_000)
    print("pass1: status=%s steps=%d emits=%d (%.1fs)"
          % (status, ex.steps, len(EMITS), time.time() - t0))
    out = []
    for (step, sva, top, n, v, idx) in EMITS:
        out.append([step, sva & 0xFFFFFFFFFFFF, top, n, v, idx])
    json.dump(out, open(os.path.join(HERE, "digest_emits.json"), "w"))
    return out


def load_pass1():
    return json.load(open(os.path.join(HERE, "digest_emits.json")))


def locate(ems):
    """Find the step numbers of the digest events."""
    # key values from streams_sample0 analysis
    marks = {
        "KPAD_IN[0]": 0x690f6094, "KPAD_IN[7]": 0xec60f2de,
        "HASH_IN[0]": 0x5f3956a2, "HASH_IN[7]": 0xda56c4e8,
        "hashB[0]": 0x04333c9d, "hashB[7]": 0x37d3cb68,
        "hashA[0]": 0x35533cc8, "hashA[7]": 0xb03cae82,
        "digest[0]": 0x42003a37, "digest[7]": 0xcc11a5fe,
        "SHA256IV[0]": 0x6a09e667,
    }
    for name, val in marks.items():
        occ = [(e[0], hex(e[1]), e[3], "%08x" % e[4])
               for e in ems if e[4] == val]
        print("%-12s %s" % (name, occ[:8]))
    # last sink write step
    sink_last = max((e[0] for e in ems if e[1] == SINK), default=-1)
    print("last SINK emit step:", sink_last)
    print("total steps:", max(e[0] for e in ems))


if __name__ == "__main__":
    if "--pass2" in sys.argv:
        import digest_prov
        digest_prov.main(int(sys.argv[sys.argv.index("--pass2") + 1]),
                         int(sys.argv[sys.argv.index("--pass2") + 2]))
    else:
        ems = pass1()
        locate(ems)
