"""probe_pt3.py — bracket the 3.62.0 record with three mints.

A: sec S,   params P          (baseline)
B: sec S+1, params P          (record should be identical -> A∩B regions)
C: sec S,   params P' (1 value tweaked) -> A△C = claims-dependent fields
Snapshot the heap at pass-0 start (first read of the pass trigger dword).

    python probe_pt3.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_READ

TRIGGER = 0x900a140

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


def runs_identical(sa, sb, minlen=32):
    out = []
    i, n = 0, min(len(sa), len(sb))
    while i < n:
        if sa[i] == sb[i]:
            j = i
            while j < n and sa[j] == sb[j]:
                j += 1
            if j - i >= minlen:
                out.append((i, j - i))
            i = j
        else:
            i += 1
    return out


def main():
    bodies = {b["sid"]: b for b in json.load(open("adj7b_bodies.json"))}
    params = dict(bodies["0015"]["body_params_dict"])
    params_c = dict(params)
    params_c["app_version"] = "9.9.9"

    S = 1771238644
    res = {}
    for tag, sec, pp in (("A", S, params), ("B", S + 1, params),
                         ("C", S, params_c)):
        emu = Probe(sec, pp)
        blob = emu.run()
        print(tag, "sec", sec, "hits", emu.hits, "snaplen",
              len(emu.snap or b""), "blob", (blob or b"").hex()[:48])
        res[tag] = {"sec": sec, "blob": blob.hex(), "snap": emu.snap.hex()}

    sa, sb, sc = (bytes.fromhex(res[t]["snap"]) for t in "ABC")
    ab = runs_identical(sa, sb)
    print("\nA∩B identical runs >=32B:", len(ab))
    for st, ln in ab[:30]:
        print("  heap %#x len %4d: %s" % (base.HEAP + st, ln, sa[st:st + 64].hex()))

    # claims-dependent: 32-B windows that differ between A and C
    diffs = [i for i in range(min(len(sa), len(sc))) if sa[i] != sc[i]]
    print("\nA△C differing bytes:", len(diffs))
    if diffs:
        # group into clusters
        clusters = []
        st = prev = diffs[0]
        for d in diffs[1:]:
            if d - prev > 8:
                clusters.append((st, prev - st + 1))
                st = d
            prev = d
        clusters.append((st, prev - st + 1))
        for st, ln in clusters[:20]:
            print("  heap %#x len %4d: A %s" % (base.HEAP + st, ln,
                                                sa[st:st + 48].hex()))
            print("                             C %s" % sc[st:st + 48].hex())

    for t in res:
        with open(os.path.join(HERE, f"snap_{t}.bin"), "wb") as f:
            f.write(bytes.fromhex(res[t]["snap"]))
        with open(os.path.join(HERE, f"blob_{t}.hex"), "w") as f:
            f.write(res[t]["blob"])
    print("\nsaved snap_A/B/C.bin + blob_A/B/C.hex")

if __name__ == "__main__":
    main()
