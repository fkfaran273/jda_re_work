"""Un-flatten the seal function (0x8c64..0xf9dc, dispatcher 0xbce0) — full-sweep.

Key structural insight: work blocks live BETWEEN dispatcher-chain entries.
A block ends with `b 0xbce0` (back-edge) or a direct branch to another block.
So: linear scan; at every `cmp REG, [const]` record the token; at every b.eq
record target; when we see the back-edge `b 0xbce0`, RESET the sim (fresh x9
from the block we just left is not valid at the head — the head compares
against prologue tokens or freshly materialized chain candidates only).
Chain regions are delimited: they only contain mov/movk/cmp/b.eq/csel/b.
"""
import sys, json
from collections import defaultdict
import capstone

sys.path.insert(0, '.')
from elf import ELF
from decryptors import LIB
from unflatten import sim_step, parse_int

DISPATCH = 0xbce0
FN = 0x8c64
FN_END = 0xf9dc
CHAIN = {'mov', 'movk', 'movz', 'cmp', 'b.eq', 'b.ne', 'csel', 'adrp', 'add', 'b'}

def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); md.detail = True
    t = e.byname['.text']; off0 = e.vaddr_to_off(t['addr'])
    insns = list(md.disasm(e.data[off0:off0 + t['size']], t['addr']))
    idx = {i.address: k for k, i in enumerate(insns)}

    # ---- prologue tokens ----
    pregs = defaultdict(set)
    for i in insns[idx[FN]:idx[DISPATCH]]:
        sim_step(pregs, i)
    saved = {r: next(iter(v)) for r, v in pregs.items()
             if r.startswith('x') and len(v) == 1 and next(iter(v)) > 0xFFFFFFFF}
    print(f"{len(saved)} prologue token regs")

    # ---- full sweep of the function ----
    regs = {r: {v} for r, v in saved.items()}
    snap = None
    t2t, alias = {}, {}
    nres = 0
    in_chain = False          # true while inside a pure dispatcher-chain run
    chain_regs = None
    k = idx[DISPATCH]
    end = idx[FN_END]
    while k < end:
        i = insns[k]
        m = i.mnemonic
        # a back-edge to DISPATCH ends a block: reset to head semantics
        if m == 'b' and parse_int(i.op_str) == DISPATCH:
            in_chain = False
            snap = None
            k += 1
            continue
        if m not in CHAIN:
            # inside a work block (or spill): kill chain state
            in_chain = False
            snap = None
            k += 1
            continue
        if m == 'cmp' and len(i.operands) == 2 and i.operands[1].type == capstone.arm64.ARM64_OP_REG:
            # candidate token: either a prologue reg or a freshly materialized one
            src = i.reg_name(i.operands[1].reg)
            vals = {v for v in regs.get(src, set()) if isinstance(v, int)}
            if src in saved:
                snap = {saved[src]}
            elif len(vals) == 1:
                snap = vals
            else:
                snap = None
            # start a chain run: keep regs as-is (they carry materialized tokens)
            in_chain = True
        elif m == 'b.eq':
            tt = parse_int(i.op_str)
            if snap is not None and len(snap) == 1:
                tok = next(iter(snap))
                if tt == DISPATCH:
                    # alias: new state = whatever got materialized into x9/x12
                    # nearby — we capture it below via nearest materialization
                    alias[tok] = None      # resolve in second pass
                else:
                    t2t[tok] = tt
            else:
                nres += 1
            snap = None
        elif m == 'b.ne':
            # cmp; b.ne HEAD; b TARGET -> fall-through block
            if snap is not None and len(snap) == 1 and k + 1 < end and insns[k + 1].mnemonic == 'b':
                t2t[next(iter(snap))] = parse_int(insns[k + 1].op_str)
            snap = None
        sim_step(regs, i)
        k += 1

    print(f"sweep: {len(t2t)} real tokens, {len(alias)} alias (to resolve), {nres} unresolved cmps")

    # ---- second pass: resolve alias targets.
    # For each alias cmp site, the new state was materialized in the OTHER reg
    # (x9 or x12) just before/after the cmp. Re-scan with per-site windows.
    regs = {r: {v} for r, v in saved.items()}
    unresolved = []
    for tok in list(alias):
        # find the cmp site for tok
        found = False
        regs2 = {r: {v} for r, v in saved.items()}
        snap2 = None
        k2 = idx[DISPATCH]
        while k2 < end:
            i = insns[k2]; m = i.mnemonic
            if m not in CHAIN:
                regs2 = {r: {v} for r, v in saved.items()}
                snap2 = None
                k2 += 1
                continue
            if m == 'cmp' and len(i.operands) == 2 and i.operands[1].type == capstone.arm64.ARM64_OP_REG:
                src = i.reg_name(i.operands[1].reg)
                vals = {v for v in regs2.get(src, set()) if isinstance(v, int)}
                snap2 = {saved[src]} if src in saved else (vals if len(vals) == 1 else None)
            elif m == 'b.eq' and parse_int(i.op_str) == DISPATCH and snap2 == {tok}:
                # new state: any >32-bit constant materialized into x9/x12 in
                # the surrounding +/-6 instructions
                lo, hi = max(idx[DISPATCH], k2 - 6), min(end, k2 + 6)
                cands = set()
                for j in range(lo, hi):
                    r = insns[j].reg_name(insns[j].operands[0].reg) if insns[j].operands and insns[j].operands[0].type == capstone.arm64.ARM64_OP_REG else None
                    if r in ('x9', 'x12'):
                        vv = {v for v in regs2.get(r, set()) if isinstance(v, int) and v > 0xFFFFFFFF}
                        cands |= vv
                # materialize across the window properly
                wregs = defaultdict(set)
                for j in range(lo, hi):
                    sim_step(wregs, insns[j])
                for r in ('x9', 'x12'):
                    vv = {v for v in wregs.get(r, set()) if isinstance(v, int) and v > 0xFFFFFFFF}
                    cands |= vv
                if len(cands) == 1:
                    alias[tok] = next(iter(cands))
                    found = True
                break
            sim_step(regs2, i)
            k2 += 1
        if not found:
            unresolved.append(tok)
            alias.pop(tok)

    # drop alias entries whose target never maps to a real block
    def resolve(tok, depth=0):
        while tok in alias and depth < 32:
            tok = alias[tok]; depth += 1
        return tok
    good = {t: g for t, g in t2t.items()}
    print(f"alias resolved: {len(alias)}; unresolved alias: {len(unresolved)}")
    json.dump({'tokens': {hex(a): hex(b) for a, b in good.items()},
               'alias': {hex(a): hex(b) for a, b in alias.items()}},
              open('seal_machine_map.json', 'w'), indent=1)
    tg = sorted(set(good.values()))
    print(f"blocks: {len(tg)} span {hex(tg[0])}..{hex(tg[-1])}" if tg else "none")
    # sanity: are our three anchors inside block targets?
    for anchor in (0xe57c, 0xbb54, 0xcf44):
        blk = [g for g in tg if g <= anchor]
        print(f"anchor {hex(anchor)}: covered by block start {hex(blk[-1]) if blk else '-'}")

if __name__ == '__main__':
    main()
