"""block_prov.py — windowed per-step prover for the BLOCK's computation window.

Adapted from digest_law/digest_prov.py.  Same mechanics (force _fast=True,
gate the hook on a step window, patch stores) but writes into block_law2/.

Usage:  python block_prov.py LO HI
"""
import inspect
import json
import os
import sys
import textwrap
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ALG = os.path.dirname(HERE)
REV = os.path.dirname(ALG)
sys.path.insert(0, REV)
sys.path.insert(0, ALG)

import fin_vm2
from fin_vm2 import FinEx
import vm_final as V
from vm_final import IDX
from dump_streams import build_descs, SEC

STEP_LOG = []
MEM_LOG = []
BLOG = []
WIN = [0, -1]

BL_PUSH, BL_POP = 0x147630, 0x147734
BL_EMIT, BL_LENQ = 0x146ed8, 0x147304
BL_SWAP, BL_CAPP = 0x147a20, 0x14784c
BL_CAPP0, BL_RAND = 0x147a18, 0x148d10
BL_OUTLEN, BL_PUSHS, BL_POPS = 0x1472e8, 0x147120, 0x147220
BL_MKITER, BL_ITNEXT, BL_ISEMPTY = 0x146558, 0x146650, 0x146474
BL_NAME = {BL_PUSH: "PUSH", BL_POP: "POP", BL_EMIT: "EMIT", BL_LENQ: "LENQ",
           BL_SWAP: "CAP_SWAP", BL_CAPP: "CAP_PUSH", BL_CAPP0: "CAP_PUSH0",
           BL_RAND: "RAND", BL_OUTLEN: "OUTLEN", BL_PUSHS: "PUSHS",
           BL_POPS: "POPS", BL_MKITER: "MKITER", BL_ITNEXT: "ITERNEXT",
           BL_ISEMPTY: "ISEMPTY"}


def make_windowed_run():
    src = textwrap.dedent(inspect.getsource(fin_vm2.FinEx.run))
    a = ("    _fast = not (_hook is not None or _pclog is not None\n"
         "                 or _dbg is not None)")
    assert a in src, "anchor A missing"
    src = src.replace(a, "    _fast = True\n"
                          "    _win = self.__dict__.get('_win')")
    b = ("        if not _fast:\n"
         "            if _hook is not None:\n"
         "                _hook(self)\n")
    assert b in src, "anchor B missing"
    src = src.replace(
        b,
        "        if _win is not None and _win[0] <= self.steps <= _win[1]:\n"
        "            _hook(self)\n"
        "        if not _fast:\n")
    ns = dict(vars(fin_vm2))
    exec(compile(src, "<block_prov_run>", "exec"), ns)
    return ns['run']


def patch_stores():
    orig_st, orig_stb = V.Ex.st, V.Ex.stbyte

    def st(self, va, v, size=8):
        if WIN[0] <= self.steps <= WIN[1]:
            MEM_LOG.append((self.steps, self.pc, "st",
                            va & 0xFFFFFFFFFFFF, size, v & 0xFFFFFFFFFFFFFFFF))
        return orig_st(self, va, v, size)

    def stbyte(self, va, b):
        if WIN[0] <= self.steps <= WIN[1]:
            MEM_LOG.append((self.steps, self.pc, "stb",
                            va & 0xFFFFFFFFFFFF, 1, b & 0xFF))
        return orig_stb(self, va, b)
    V.Ex.st, V.Ex.stbyte = st, stbyte
    return orig_st, orig_stb


def make_hook():
    prev = {}
    first = [True]

    def hook(e):
        R = e.R
        ev = []
        if first[0]:
            first[0] = False
            prev.update(R)
        else:
            for k, v in R.items():
                if prev.get(k, -1) != v:
                    ev.append((k, v & 0xFFFFFFFF))
        for k, v in ev:
            prev[k] = v
        pc = e.pc
        k = IDX.get(pc)
        mnem, ops = (V.FAST[k][0], V.FAST[k][1]) if k is not None else ("?", "?")
        if mnem == "bl":
            t = V.pt(ops)
            nm = BL_NAME.get(t)
            if nm:
                BLOG.append((e.steps, pc, nm, R.get("x1", 0) & 0xFFFFFFFFFFFF,
                             R.get("w2", 0) & 0xFFFFFFFF,
                             R.get("w3", 0) & 0xFFFFFFFF,
                             R.get("x0", 0) & 0xFFFFFFFFFFFF))
        STEP_LOG.append((e.steps, pc, mnem, ops, ev))
    return hook


def main(lo, hi):
    WIN[0], WIN[1] = lo, hi
    STEP_LOG[:] = []
    MEM_LOG[:] = []
    BLOG[:] = []
    run_win = make_windowed_run()
    orig_run = FinEx.run
    FinEx.run = run_win
    descs = build_descs()
    ex = FinEx(SEC, descs)
    hook = make_hook()
    ex.__dict__['_win'] = [lo, hi]
    ex.__dict__['_step_hook'] = hook
    ost = patch_stores()
    t0 = time.time()
    status = ex.run(max_steps=60_000_000)
    FinEx.run = orig_run
    V.Ex.st, V.Ex.stbyte = ost
    print("pass2 [%d..%d]: status=%s steps=%d log=%d bl=%d mem=%d (%.1fs)"
          % (lo, hi, status, ex.steps, len(STEP_LOG), len(BLOG), len(MEM_LOG),
             time.time() - t0))

    base = os.path.join(HERE, "blockprov_%d_%d" % (lo, hi))
    json.dump({"steps": [[s, pc, m, ops, ev] for (s, pc, m, ops, ev) in STEP_LOG],
               "bl": BLOG, "mem": MEM_LOG}, open(base + ".json", "w"))
    bl_by_step = {}
    for (s, pc, nm, x1, w2, w3, x0) in BLOG:
        bl_by_step.setdefault(s, []).append((nm, x1, w2, w3, x0))
    mem_by_step = {}
    for (s, pc, kind, va, size, val) in MEM_LOG:
        mem_by_step.setdefault(s, []).append((kind, va, size, val))
    with open(base + ".txt", "w") as f:
        for (s, pc, mnem, ops, ev) in STEP_LOG:
            line = "%8d %06x %-6s %s" % (s, pc, mnem, ops)
            for (nm, x1, w2, w3, x0) in bl_by_step.get(s, ()):
                line += "  | %s x1=%x w2=%x w3=%08x x0=%x" % (nm, x1, w2, w3, x0)
            for (kind, va, size, val) in mem_by_step.get(s, ()):
                line += "  | %s [%x] = %x" % (kind, va, val)
            if ev:
                line += "  ; " + " ".join("%s=%x" % (k, v) for k, v in ev)
            f.write(line + "\n")
    print("wrote", base + ".txt")


if __name__ == "__main__":
    main(int(sys.argv[1]), int(sys.argv[2]))