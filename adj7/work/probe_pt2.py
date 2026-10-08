"""probe_pt2.py — known-plaintext oracle for the 3.62.0 whitening.

Arms a heap+stack read trace right after the header PRNG is done (8th
plt rand()), segments it at the 16 KB-copy pass boundaries, snapshots the
heap at pass 0 and pass 1, and captures the final blob.

    python probe_pt2.py [sec]
"""
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

SEC = int(sys.argv[1]) if len(sys.argv) > 1 else 1771238644

class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.out_buf = None
        self.nrand = 0
        self._on = False
        self.reads = []          # (addr, size)
        self.snaps = {}
        self.mark = 0            # kb-copy first-dword read counter

    def plt_dispatch(self, uc, name):
        r = super().plt_dispatch(uc, name)
        if name in ("rand", "random"):
            self.nrand += 1
            if self.nrand == 8 and not self._on:
                self._on = True
                self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                                 begin=base.HEAP, end=base.STACK + base.STACK_SZ)
        return r

    def on_read(self, uc, access, address, size, value, user):
        self.reads.append((address, size))

    def jni_call(self, uc, idx, x):
        if idx == 208 and x[3] == 304:
            self.out_buf = x[4]
            self._on = False
        return super().jni_call(uc, idx, x)

    def run(self, payload, mapobj, arg4=8):
        out = super().run(payload=payload, mapobj=mapobj, arg4=arg4)
        if out is None and self.out_buf is not None:
            out = bytes(self.uc.mem_read(self.out_buf, 304))
        self.blob = out
        return out


def main():
    bodies = {b["sid"]: b for b in
              json.load(open("adj7b_bodies.json"))}
    params = dict(bodies["0015"]["body_params_dict"])
    emu = Probe(SEC)
    out = emu.run(payload=bytes(32), mapobj=params)
    blob = out
    print("sec", SEC, "blob", blob.hex() if blob else None)
    print("read log entries:", len(emu.reads))

    # the KB copy: a 4-byte-aligned address read 16 times (dword granularity)
    cnt = Counter(a & ~3 for a, s in emu.reads if s == 4)
    kb_addrs = [a for a, c in cnt.items() if c == 16]
    print("dwords read exactly 16x:", len(kb_addrs))
    if kb_addrs:
        lo, hi = min(kb_addrs), max(kb_addrs)
        print("KB copy range: %#x .. %#x (span %d)" % (lo, hi, hi - lo + 4))

    # pass boundaries: reads of the lowest KB address
    k0 = min(kb_addrs)
    times = [i for i, (a, s) in enumerate(emu.reads) if s == 4 and (a & ~3) == k0]
    print("pass starts:", len(times))
    # input reads per pass: addresses read between t_i and t_i+1 that are NOT the KB
    per_pass = []
    for p in range(len(times) - 1):
        seg = emu.reads[times[p]:times[p + 1]]
        addrs = Counter(a & ~3 for a, s in seg if s == 4 and not (lo <= (a & ~3) <= hi))
        per_pass.append(addrs)
    for p in range(min(3, len(per_pass))):
        top = per_pass[p].most_common(8)
        print("pass %d non-KB reads:" % p, [(hex(a), c) for a, c in top])

    # the record: an address read once per pass -> appears in every pass window
    if per_pass:
        common = set(per_pass[0])
        for ap in per_pass[1:]:
            common &= set(ap)
        rec_addrs = sorted(common)
        print("addresses read in EVERY pass:", len(rec_addrs),
              [hex(a) for a in rec_addrs[:6]], "..." if len(rec_addrs) > 6 else "")

    json.dump({"sec": SEC, "blob": blob.hex(), "kb_lo": lo if kb_addrs else None,
               "kb_hi": hi if kb_addrs else None,
               "reads_head": [(a, s) for a, s in emu.reads[:2000]]},
              open(os.path.join(HERE, "probe_pt2_out.json"), "w"), indent=1)

if __name__ == "__main__":
    main()
