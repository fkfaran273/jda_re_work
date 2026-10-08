"""commit2_fresh.py — fresh mint at a NEW second with a THIRD claims variant.

D: sec 1771239000, app_version "7.7.7" (and session_count bumped).
Verifies the commit2 law predictions against the genuine heap.

    python commit2_fresh.py
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
os.chdir(os.path.join(ROOT, "adj7_work"))
sys.path.insert(0, os.path.join(ROOT, "adj7_work"))
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_READ

TRIGGER = 0x900A140
SEC = 1771239000


class Probe(base.Emu):
    def __init__(self, sec, params):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.params = params
        self.out_buf = None
        self.nrand = 0
        self._on = False
        self.hits = 0
        self.snap = None

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._on:
                self._on = True
                self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                                 begin=TRIGGER, end=TRIGGER + 4)
        return r

    def on_read(self, uc, access, address, size, value, user):
        self.hits += 1
        if self.hits == 1:
            self.snap = bytes(uc.mem_read(base.HEAP, self.brk - base.HEAP))

    def jni_call(self, uc, idx, x):
        if idx == 208 and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)

    def run(self, payload=bytes(32), mapobj=None, arg4=8):
        out = super().run(payload=payload, mapobj=self.params, arg4=arg4)
        if out is None and self.out_buf is not None:
            out = bytes(self.uc.mem_read(self.out_buf, 304))
        self.blob = out
        return out


def main():
    bodies = {b["sid"]: b for b in
              json.load(open("adj7b_bodies.json"))}
    params = dict(bodies["0015"]["body_params_dict"])
    params["app_version"] = "7.7.7"
    emu = Probe(SEC, params)
    blob = emu.run()
    print("sec", SEC, "blob", (blob or b"").hex()[:48])
    snap = emu.snap
    open(os.path.join(HERE, "commit2_snap_D.bin"), "wb").write(snap or b"")
    if blob:
        open(os.path.join(HERE, "commit2_blob_D.hex"), "w").write(blob.hex())
    # extract c20/c32 at the known structure offsets
    HEAP = 0x9000000
    for off in (0x900bb84, 0x900c574, 0x900cf84, 0x900db94):
        print("c20@%#x:" % off, snap[off - HEAP:off - HEAP + 20].hex())
    for off in (0x900be98, 0x900c888, 0x900d298, 0x900dea8):
        print("c32@%#x:" % off, snap[off - HEAP:off - HEAP + 32].hex())
    # claims-dependent text check
    print("app_version in raw map buf:", b"7.7.7" in snap)


if __name__ == "__main__":
    main()
