"""fill_probe.py - dump the BUILT descriptors (the 11 wire-builder objects) of
the emulated signing path, as a function of the experiment inputs.

The 11 descriptors are created by the VM wire builder (bl 0x147d3c nodes,
{nbytes u32; ptr}) and passed to the serializer entry 0x100094 by the bl at
0x12d39c with w2 = 11.  We hook pc == 0x12d39c and read the varargs:
  va slots 0..4  = x3..x7
  va slots 5..10 = [sp], [sp+8], ... [sp+0x28]
Each slot is a node: nbytes = u32[node], data = u64[node+8].

va slot -> build_idx mapping (fin_result.md VA_ORDER): [0,9,8,4,2,7,10,5,1,6,3]
  #0 36 dw (W0 | X | tile*8 | T0 T1 T2)   #4 8 dw   #2 1 dw
  #7 claims len   #8 anchor  #9 cert-SHA1  #10 claims  #5=#6=0  #1=#3 empty

Usage:
  python fill_probe.py --runs '[{"tag":"base"}, {"tag":"nsec+1","cfg":{"nsec":500000001}}]'
  python fill_probe.py --list base nsec+1 ...   (re-analyze existing dumps)
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
OUTDIR = os.path.join(HERE, "fill_runs")


def run_one(cfg, tag, timeout_us=900_000_000):
    e = E.Emu(cfg=cfg)
    hits = []

    def hook_ser(uc, address, size, ud):
        regs = [UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        slots = [uc.reg_read(r) for r in regs]
        sp = uc.reg_read(UC_ARM64_REG_SP)
        for k in range(6):
            try:
                v = struct.unpack("<Q", uc.mem_read(sp + 8 * k, 8))[0]
            except UcError:
                v = 0
            slots.append(v)
        hits.append({"x0": uc.reg_read(UC_ARM64_REG_X0),
                     "x1": uc.reg_read(UC_ARM64_REG_X1),
                     "x2": uc.reg_read(UC_ARM64_REG_X2),
                     "slots": slots})

    e.mu.hook_add(UC_HOOK_CODE, hook_ser, begin=SER_PC, end=SER_PC)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign", timeout_us=timeout_us)

    mu = e.mu
    descs = []       # per serializer hit: list of {va, build_idx, node, nbytes, data, hex}
    for h in hits:
        ds = []
        for va, node in enumerate(h["slots"]):
            bi = VA_ORDER[va] if va < len(VA_ORDER) else va
            ent = {"va": va, "build_idx": bi, "node": node}
            try:
                nb = struct.unpack("<I", mu.mem_read(node, 4))[0]
                ptr = struct.unpack("<Q", mu.mem_read(node + 8, 8))[0]
                if 0 < nb <= 0x10000 and ptr:
                    raw = bytes(mu.mem_read(ptr, nb))
                    ent.update({"nbytes": nb, "data": ptr, "hex": raw.hex()})
                else:
                    ent.update({"nbytes": nb, "data": ptr})
            except UcError:
                pass
            ds.append(ent)
        descs.append(ds)

    # parse the region words from the LAST complete 11-descriptor hit
    region = None
    for ds in reversed(descs):
        by = {d["build_idx"]: d for d in ds if "hex" in d}
        if 0 in by and by[0].get("nbytes") == 144:
            d0 = struct.unpack(">36I", bytes.fromhex(by[0]["hex"]))
            # minimal period of the tile tail (words 2..35)
            tail = list(d0[2:])
            per = None
            for p in (1, 2, 3, 4, 6, 8, 12, 16, 17, 34):
                if all(tail[i] == tail[i + p] for i in range(len(tail) - p)):
                    per = p
                    break
            region = {
                "W0": "%08x" % d0[0], "X": "%08x" % d0[1],
                "tail_period": per,
                "U": ["%08x" % w for w in tail[:8]],
                "d2": ("0x%08x" % struct.unpack(">I", bytes.fromhex(by[2]["hex"]))[0]
                       if 2 in by and by[2].get("nbytes") == 4 else None),
                "d4": (["%08x" % w for w in struct.unpack(">8I", bytes.fromhex(by[4]["hex"]))]
                       if 4 in by and by[4].get("nbytes") == 32 else None),
            }
            break

    blob = e.result.get("blob")
    out = {
        "tag": tag,
        "cfg": {k: v for k, v in e.cfg.items()},
        "stopped": st,
        "wall": getattr(e, "wall", 0),
        "insns": e.icount,
        "n_desc_hits": len(hits),
        "descs": descs,
        "region": region,
        "blob": blob.hex() if blob else None,
        "rand": [(i, v, hex(lr)) for i, v, lr in e.rand_calls],
        "srand": e.srand_log,
        "clocks": [c for c in e.calls if c[0] in ("clock_gettime", "gettimeofday", "time")],
        "ctx_sha": None,
    }
    ctx = e.ctx_bytes()
    import hashlib
    out["ctx_sha"] = hashlib.sha256(ctx).hexdigest()[:16]
    return out


def main_runs(specs):
    import os as _os
    _os.makedirs(OUTDIR, exist_ok=True)
    for spec in specs:
        tag = spec["tag"]
        cfg = spec.get("cfg", {})
        print("=== run %s cfg=%s" % (tag, json.dumps(cfg, default=str)), flush=True)
        out = run_one(cfg, tag)
        p = _os.path.join(OUTDIR, tag + ".json")
        json.dump(out, open(p, "w"), indent=1, default=str)
        r = out["region"]
        print("    stopped=%s wall=%.1fs desc_hits=%d" %
              (out["stopped"], out["wall"], out["n_desc_hits"]), flush=True)
        if r:
            print("    W0=%s X=%s U=%s d2=%s d4=%s" %
                  (r["W0"], r["X"], r["U"][:4], r["d2"], r["d4"][:4] if r["d4"] else None), flush=True)
        print("    saved %s" % p, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=str, default=None,
                    help='JSON list of {tag, cfg} specs')
    ap.add_argument("--list", type=str, nargs="*", default=None,
                    help="tags to re-print from fill_runs/")
    args = ap.parse_args()

    if args.list is not None:
        for tag in args.list:
            p = os.path.join(OUTDIR, tag + ".json")
            d = json.load(open(p))
            print("== %s: stopped=%s region=%s" % (tag, d["stopped"], d["region"]))
        return

    os.makedirs(OUTDIR, exist_ok=True)
    specs = json.loads(args.runs) if args.runs else [{"tag": "base"}]
    for spec in specs:
        tag = spec["tag"]
        cfg = spec.get("cfg", {})
        print("=== run %s cfg=%s" % (tag, json.dumps(cfg, default=str)), flush=True)
        out = run_one(cfg, tag)
        p = os.path.join(OUTDIR, tag + ".json")
        json.dump(out, open(p, "w"), indent=1, default=str)
        r = out["region"]
        print("    stopped=%s wall=%.1fs insns=%s desc_hits=%d" %
              (out["stopped"], out["wall"], out["insns"], out["n_desc_hits"]))
        print("    W0=%s X=%s U=%s d2=%s" % (r["W0"], r["X"], r["U"], r["d2"]) if r else "    NO REGION")
        if r and r["d4"]:
            print("    d4=%s" % " ".join(r["d4"]))
        print("    saved %s" % p, flush=True)


if __name__ == "__main__":
    main()
