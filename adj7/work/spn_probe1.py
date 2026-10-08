"""spn_probe1.py — fresh fully-instrumented mint (values on heap reads too).

Same mint as v3 (sid 0015, sec 1771238644) so the blob must equal v3_blob.hex
and the write stream should match v3_writes.txt.  New: read values, heap
snapshots at pass triggers, everything logged for offline SPN mining.

    python spn_probe1.py [sec] [sid]
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC

SEC = int(sys.argv[1]) if len(sys.argv) > 1 else 1771238644
SID = sys.argv[2] if len(sys.argv) > 2 else "0015"

TRIGGER = 0x900a140          # probe_v3 pass trigger
KB = 0x900a6a8               # verified KB362 location (LE view)


class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.out_buf = None
        self.nrand = 0
        self._on = False
        self.reads = []       # (addr, size, value)
        self.writes = []      # (addr, size, value)
        self.passn = 0
        self.snaps = {}
        self.t0 = time.time()

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._on:
                self._on = True
                self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                                 begin=0x7000000, end=0x9800000)
                self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write,
                                 begin=0x7000000, end=0x9800000)
                print("armed at nrand=8, t=%.1fs" % (time.time() - self.t0))
        return r

    def on_read(self, uc, access, address, size, value, user):
        self.reads.append((address, size, value))
        if address == TRIGGER and size == 4:
            self.passn += 1
            if self.passn <= 17:
                try:
                    heap = bytes(uc.mem_read(0x9000000,
                                             self.brk - 0x9000000))
                    self.snaps[self.passn] = heap
                except Exception as e:
                    print("snap err", e)

    def on_write(self, uc, access, address, size, value, user):
        self.writes.append((address, size, value))

    def jni_call(self, uc, idx, x):
        if idx == 208 and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)

    def run(self, payload=bytes(32), mapobj=None, arg4=8):
        out = super().run(payload=payload, mapobj=mapobj, arg4=arg4)
        if out is None and self.out_buf is not None:
            out = bytes(self.uc.mem_read(self.out_buf, 304))
        self.blob = out
        return out


def main():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies[SID]["body_params_dict"])
    emu = Probe(SEC)
    blob = emu.run(mapobj=params)
    print("sec", SEC, "sid", SID, "blob", blob.hex()[:48] if blob else None,
          "passes", emu.passn, "reads", len(emu.reads),
          "writes", len(emu.writes), "t=%.1fs" % (time.time() - emu.t0))
    want = open(os.path.join(HERE, "v3_blob.hex")).read().strip()
    got = blob.hex() if blob else ""
    print("MATCH v3_blob:", got == want)
    with open(os.path.join(HERE, "v4_writes.txt"), "w") as f:
        for a, s, v in emu.writes:
            f.write("%x %d %x\n" % (a, s, v))
    with open(os.path.join(HERE, "v4_reads.txt"), "w") as f:
        for a, s, v in emu.reads:
            f.write("%x %d %x\n" % (a, s, v))
    for p, heap in emu.snaps.items():
        with open(os.path.join(HERE, "v4_snap_p%d.bin" % p), "wb") as f:
            f.write(heap)
    with open(os.path.join(HERE, "v4_blob.hex"), "w") as f:
        f.write(got)
    print("saved v4_* files")


if __name__ == "__main__":
    main()
