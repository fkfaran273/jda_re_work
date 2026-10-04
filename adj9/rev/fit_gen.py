"""fit_gen.py - minimal region dumper for the F-fitting table.

Same emulator as fill_probe.py (emu_8d6f4.Emu) but stores ONLY the three
region descriptors (#0/#2/#4) as hex, so new runs cost ~10 KB each instead
of hundreds of MB.  Cross-checks the serializer-node pointers against the
fixed descriptor VAs (0x300000FFD20 d2 / 0x300000FFD30 d4 / 0x300000FFD50 d0).

Usage (single):
  python fit_gen.py --out fit_runs/base2.json --cfg '{"usec":500000}'
Batch is driven by fit_batch.py (parallel workers).
"""
import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

SER_PC = 0x12D39C
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
ADDR = {0: 0x300000FFD50, 2: 0x300000FFD20, 4: 0x300000FFD30}
NB = {0: 144, 2: 4, 4: 32}


def emu_V(cfg):
    us = cfg.get("usec", 500000) + 4000
    sec = cfg.get("sec", 1789240512) + us // 1000000
    return sec ^ (us % 1000000)


def run_one(cfg, out_path=None):
    e = E.Emu(cfg=cfg)
    hits = []

    def hook_ser(uc, address, size, ud):
        regs = [UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        slots = [uc.reg_read(r) for r in regs]
        sp = uc.reg_read(UC_ARM64_REG_SP)
        for k in range(6):
            try:
                slots.append(struct.unpack("<Q", uc.mem_read(sp + 8 * k, 8))[0])
            except UcError:
                slots.append(0)
        hits.append(slots)

    e.mu.hook_add(UC_HOOK_CODE, hook_ser, begin=SER_PC, end=SER_PC)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign",
               timeout_us=900_000_000)
    mu = e.mu
    rec = {"cfg": {k: v for k, v in e.cfg.items() if k != "props"},
           "stopped": st, "wall": getattr(e, "wall", 0),
           "n_desc_hits": len(hits),
           "V": emu_V(e.cfg),
           "pid": e.cfg["pid"], "tid": e.cfg["tid"]}
    # region from the LAST serializer hit's node pointers
    if hits:
        slots = hits[-1]
        node = {}
        for va, nd in enumerate(slots):
            node[VA_ORDER[va]] = nd
        for bi in (0, 2, 4):
            nd = node.get(bi)
            if not nd:
                continue
            try:
                nbytes = struct.unpack("<I", mu.mem_read(nd, 4))[0]
                ptr = struct.unpack("<Q", mu.mem_read(nd + 8, 8))[0]
                if nbytes == NB[bi] and ptr:
                    rec["d%d" % bi] = bytes(mu.mem_read(ptr, nbytes)).hex()
                    rec["d%d_ptr" % bi] = ptr
            except UcError:
                pass
    # fixed VAs (authoritative per the task statement)
    for bi in (0, 2, 4):
        try:
            raw = bytes(mu.mem_read(ADDR[bi], NB[bi]))
            rec["va%d" % bi] = raw.hex()
            if rec.get("d%d" % bi) in (None, raw.hex()):
                rec["d%d" % bi] = raw.hex()
        except UcError:
            pass
    rec["node_va_match"] = all(rec.get("d%d" % bi) == rec.get("va%d" % bi)
                              for bi in (0, 2, 4) if "va%d" % bi in rec)
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        json.dump(rec, open(out_path, "w"), indent=1, default=str)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--cfg", default="{}")
    a = ap.parse_args()
    rec = run_one(json.loads(a.cfg), a.out)
    print("saved", a.out, "V=%08x" % rec["V"], "match=", rec["node_va_match"])
    for bi in (0, 2, 4):
        print("  d%d=%s" % (bi, rec.get("d%d" % bi)))


if __name__ == "__main__":
    main()
