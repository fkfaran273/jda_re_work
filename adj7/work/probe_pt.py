"""probe_pt.py — known-plaintext hunt for the 3.62.0 record.

Runs the genuine lib under unicorn twice (same claims, different seconds),
snapshots the heap at the first KB362 read (whitening chunk 0 starts, the
record is fully assembled), and diffs the snapshots: byte-identical regions
are the second-independent plaintext record.

    python probe_pt.py
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)          # adj7s3_emu loads the .so via a relative path
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

import adj7s3_emu as base
from unicorn import UC_HOOK_MEM_READ

class Probe(base.Emu):
    def __init__(self, sec):
        super().__init__(verbose=False)
        self.fixed_time = sec
        self.kb_base = base.BASE + 0xd20a0
        self.kb_n = 0
        self.snaps = {}
        self.uc.hook_add(UC_HOOK_MEM_READ, self.on_kb_read,
                         begin=self.kb_base, end=self.kb_base + 0x100)
        self.out_buf = None

    def on_kb_read(self, uc, access, address, size, value, user):
        self.kb_n += 1
        if self.kb_n == 1:
            self.brk_now = self.brk
            self.snaps[1] = bytes(uc.mem_read(base.HEAP, self.brk - base.HEAP))
        elif self.kb_n == 65:  # start of chunk 1
            self.snaps[65] = bytes(uc.mem_read(base.HEAP, self.brk - base.HEAP))

    def jni_call(self, uc, idx, x):
        if idx == 208 and self.out_buf is None and x[3] == 304:
            self.out_buf = x[4]
        return super().jni_call(uc, idx, x)

    def run(self, payload, mapobj, arg4=8):
        out = super().run(payload=payload, mapobj=mapobj, arg4=arg4)
        if out is None and self.out_buf is not None:
            out = bytes(self.uc.mem_read(self.out_buf, 304))
        self.blob = out
        return out


def main():
    bodies = {b["sid"]: b for b in
              json.load(open(os.path.join(WORK, "adj7b_bodies.json")))}
    params = dict(bodies["0015"]["body_params_dict"])
    results = {}
    for tag, sec in (("A", 1771238644), ("B", 1771238645)):
        emu = Probe(sec)
        out = emu.run(payload=bytes(32), mapobj=params)
        print(tag, "sec", sec, "blob:", (out or b"").hex()[:64], "kb_reads:", emu.kb_n)
        results[tag] = {"sec": sec, "blob": (out or b"").hex(),
                        "snap1": emu.snaps.get(1, b"").hex(),
                        "snap65": emu.snaps.get(65, b"").hex()}
    with open(os.path.join(HERE, "probe_pt_out.json"), "w") as f:
        json.dump(results, f)

    a, b = results["A"], results["B"]
    sa, sb = bytes.fromhex(a["snap1"]), bytes.fromhex(b["snap1"])
    print("snap lens:", len(sa), len(sb))
    # identical runs >= 64 bytes
    runs = []
    i = 0
    n = min(len(sa), len(sb))
    while i < n:
        if sa[i] == sb[i]:
            j = i
            while j < n and sa[j] == sb[j]:
                j += 1
            if j - i >= 64:
                runs.append((i, j - i))
            i = j
        else:
            i += 1
    print("identical runs >=64B:", len(runs))
    for st, ln in runs[:20]:
        print("  heap %#x len %d: %s" % (base.HEAP + st, ln, sa[st:st + 48].hex()))

if __name__ == "__main__":
    main()
