"""Walk the un-flattened seal machine (fn 0x8c64, dispatcher 0xbce0) in
execution order with semantic per-block summaries."""
import sys, pickle, json
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
    strs = pickle.load(open('strings_final.pkl', 'rb'))
    mp = json.load(open('seal_machine_map.json'))
    t2t = {int(k, 16): int(v, 16) for k, v in mp['tokens'].items()}
    alias = {int(k, 16): int(v, 16) for k, v in mp['alias'].items()}

    # prologue entry token: x9 at DISPATCH (re-materialize from prologue)
    pregs = defaultdict(set)
    for i in insns[idx[FN]:idx[DISPATCH]]:
        sim_step(pregs, i)
    saved = {r: next(iter(v)) for r, v in pregs.items()
             if r.startswith('x') and len(v) == 1 and next(iter(v)) > 0xFFFFFFFF}
    entry = {v for v in saved.values()}

    def resolve(tok, depth=0):
        while tok in alias and depth < 32:
            tok = alias[tok]; depth += 1
        return tok

    def block_info(start):
        """simulate a block: notes + exits"""
        k = idx.get(start)
        regs = defaultdict(set)
        notes = []
        adrp_reg = {}
        seq = []
        if k is None:
            return set(), [], None, ['<unmapped>']
        for j in range(k, min(k + 5000, idx[FN_END])):
            i = insns[j]
            seq.append(i)
            m = i.mnemonic
            if m == 'adrp' and len(i.operands) == 2 and 0x151000 <= i.operands[1].imm <= 0x156000:
                adrp_reg[i.reg_name(i.operands[0].reg)] = i.operands[1].imm
            elif m == 'add' and len(i.operands) == 3 and i.operands[1].type == capstone.arm64.ARM64_OP_REG \
                    and i.operands[2].type == capstone.arm64.ARM64_OP_IMM:
                r = i.reg_name(i.operands[1].reg)
                if r in adrp_reg:
                    va = adrp_reg[r] + i.operands[2].imm
                    if va in strs:
                        notes.append(f'str@0x{va:x}="{strs[va][2][:40]}"')
                    elif 0x1555c0 <= va < 0x155a00:
                        notes.append(f'flag@0x{va:x}')
                    adrp_reg.pop(r)
            elif m == 'bl':
                tt = parse_int(i.op_str)
                name = e.plt_map.get(tt)
                notes.append(f'call {name or hex(tt)}')
            elif m == 'b':
                tt = parse_int(i.op_str)
                if tt == DISPATCH:
                    return ({v for v in regs.get('x9', set()) if isinstance(v, int) and v > 0xFFFFFFFF},
                            seq, None, notes)
                return set(), seq, tt, notes
            elif m == 'ret':
                return set(), seq, 'ret', notes
            elif m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                return ({v for v in regs.get('x9', set()) if isinstance(v, int) and v > 0xFFFFFFFF},
                        seq, ('cond', parse_int(i.op_str.split(',')[-1])), notes)
            sim_step(regs, i)
        return set(), seq, 'runaway', notes

    block2tok = {}
    for tok, tgt in t2t.items():
        block2tok.setdefault(tgt, tok)

    # ---- BFS/DFS walk from entry token ----
    order = []
    seen = set()
    def dfs(tok, depth=0):
        if tok in seen or depth > 80:
            return
        seen.add(tok)
        tgt = t2t.get(tok)
        if tgt is None:
            return
        nxt, seq, exitbr, notes = block_info(tgt)
        order.append((tok, tgt))
        print(f"[{len(order):3d}] blk 0x{tgt:05x} n={len(seq):4d} exit={hex(exitbr) if isinstance(exitbr,int) else exitbr}")
        for n in notes[:10]:
            print(f"        {n}")
        succs = {resolve(v) for v in nxt}
        if isinstance(exitbr, int) and exitbr in block2tok:
            succs.add(block2tok[exitbr])
        if isinstance(exitbr, tuple) and exitbr[1] and exitbr[1] in block2tok:
            succs.add(block2tok[exitbr[1]])
        for s in sorted(succs):
            dfs(s, depth + 1)

    print(f"entry candidates: {[hex(v) for v in entry]}")
    started = False
    for v in sorted(entry):
        rv = resolve(v)
        if rv in t2t:
            dfs(rv)
            started = True
            break
    if not started:
        print("no entry; walking all blocks in address order")
        for tok, tgt in sorted(t2t.items(), key=lambda x: x[1]):
            nxt, seq, exitbr, notes = block_info(tgt)
            print(f"blk 0x{tgt:05x} n={len(seq):4d} exit={hex(exitbr) if isinstance(exitbr,int) else exitbr}")
            for n in notes[:8]:
                print(f"        {n}")
    print(f"\nvisited {len(order)} blocks of {len(t2t)} tokens")

if __name__ == '__main__':
    main()
