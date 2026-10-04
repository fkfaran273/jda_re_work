"""Full-sweep un-flatten of the 0x10594 machine (blob builder fn 0xe740..0x131dc).

Differences vs seal_unflatten.py:
- sim tracks EVERY instruction in range (materializations inside work blocks count)
- candidates accepted only from `cmp x8/x9, REG` (state regs) + b.eq
- post-filter: keep tokens whose target block transitively ends with b #0x10594
  or ret (kills opaque-predicate mini-machines' false edges)
"""
import sys, json
from collections import defaultdict
import capstone

sys.path.insert(0, '.')
from elf import ELF
from decryptors import LIB
from unflatten import sim_step, parse_int

DISPATCH = 0x10594
FN = 0xe740
FN_END = 0x131dc

def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); md.detail = True
    t = e.byname['.text']; off0 = e.vaddr_to_off(t['addr'])
    insns = list(md.disasm(e.data[off0:off0 + t['size']], t['addr']))
    idx = {i.address: k for k, i in enumerate(insns)}
    end = idx[FN_END]

    # prologue tokens (may be partly wrong fn — filtered later by back-edge test)
    pregs = defaultdict(set)
    for i in insns[idx[FN]:idx[DISPATCH]]:
        sim_step(pregs, i)
    saved = {r: next(iter(v)) for r, v in pregs.items()
             if r.startswith('x') and len(v) == 1 and next(iter(v)) > 0xFFFFFFFF}

    regs = {r: {v} for r, v in saved.items()}
    snap = None
    raw_pairs = []          # (token, target, cmp_addr)
    alias_pairs = []
    for k in range(idx[DISPATCH], end):
        i = insns[k]
        m = i.mnemonic
        if m == 'cmp' and len(i.operands) == 2:
            op0 = i.operands[0]; op1 = i.operands[1]
            if op0.type == capstone.arm64.ARM64_OP_REG and op1.type == capstone.arm64.ARM64_OP_REG:
                r0 = i.reg_name(op0.reg); r1 = i.reg_name(op1.reg)
                if r0 in ('x8', 'x9'):          # state-carrying regs of this head
                    vals = {v for v in regs.get(r1, set()) if isinstance(v, int)}
                    snap = (vals if vals else None)
                else:
                    snap = None
            else:
                snap = None
        elif m == 'b.eq':
            tt = parse_int(i.op_str)
            if snap is not None and len(snap) == 1:
                tok = next(iter(snap))
                if tok > 0xFFFFFFFF:
                    if tt == DISPATCH:
                        alias_pairs.append((tok, i.address))
                    else:
                        raw_pairs.append((tok, tt, i.address))
            snap = None
        elif m == 'b.ne':
            # cmp; b.ne HEAD; b TARGET  ->  fall-through block
            if snap is not None and len(snap) == 1 and k + 1 < end and insns[k + 1].mnemonic == 'b':
                tt = parse_int(insns[k + 1].op_str)
                if tt and tt != DISPATCH:
                    raw_pairs.append((next(iter(snap)), tt, i.address))
            snap = None
        elif m == 'b':
            if parse_int(i.op_str) == DISPATCH:
                regs = {r: {v} for r, v in saved.items()}   # back-edge: reset to prologue vals
            snap = None
        sim_step(regs, i)

    print(f"raw pairs: {len(raw_pairs)}, alias sites: {len(alias_pairs)}")

    # ---- filter: target block must end (transitively) at b DISPATCH or ret ----
    def block_exit(start):
        k = idx.get(start)
        if k is None:
            return None
        for j in range(k, min(k + 3000, end)):
            i = insns[j]
            if i.mnemonic == 'b':
                return parse_int(i.op_str)
            if i.mnemonic == 'ret':
                return 'ret'
        return 'runaway'

    good = {}
    for tok, tt, ca in raw_pairs:
        # walk forward from target: allow up to 3 chained direct branches
        cur = tt
        ok = False
        for _ in range(3):
            ex = block_exit(cur)
            if ex == DISPATCH or ex == 'ret':
                ok = True; break
            if isinstance(ex, int) and idx.get(ex) is not None and ex > cur:
                cur = ex
            else:
                break
        if ok:
            good[tok] = tt
    print(f"after back-edge filter: {len(good)} real tokens")
    json.dump({'tokens': {hex(a): hex(b) for a, b in good.items()}},
              open('machine10594_map.json', 'w'), indent=1)
    tg = sorted(set(good.values()))
    print(f"blocks: {len(tg)} span {hex(tg[0])}..{hex(tg[-1])}" if tg else "none")
    known = {0x117dc, 0x1253c, 0x11b94, 0x12f4c, 0x1300c, 0x11874, 0x118b4, 0x13138, 0x11f6c, 0x12b74}
    print("known anchors covered:", {hex(a): (a in set(good.values())) for a in known})

if __name__ == '__main__':
    main()
