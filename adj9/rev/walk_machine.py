"""DFS the un-flattened 0x24a40 state machine and print every block with a
semantic summary: resolved imports (PLT), string-table decrypts (decoded via
strings_final.pkl), one-shot CAS guards, and struct stores."""
import sys, pickle
from collections import defaultdict
import capstone

sys.path.insert(0, '.')
from elf import ELF
from decryptors import LIB
from unflatten import sim_step, parse_int, DISPATCH

def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); md.detail = True
    t = e.byname['.text']; off0 = e.vaddr_to_off(t['addr'])
    insns = list(md.disasm(e.data[off0:off0 + t['size']], t['addr']))
    idx = {i.address: k for k, i in enumerate(insns)}
    strs = pickle.load(open('strings_final.pkl', 'rb'))

    # --- prologue tokens (same as unflatten.py) ---
    fn_start = None
    for k in range(idx[DISPATCH], 0, -1):
        i = insns[k]
        if i.mnemonic == 'paciasp' or (i.mnemonic == 'stp' and i.op_str.startswith('x29, x30')):
            fn_start = i.address; break
    pregs = defaultdict(set)
    for i in insns[idx[fn_start]:idx[DISPATCH]]:
        sim_step(pregs, i)
    saved = {r: next(iter(v)) for r, v in pregs.items()
             if r.startswith('x') and len(v) == 1 and next(iter(v)) > 0xFFFF}

    # --- dispatcher chain ---
    regs = {r: {v} for r, v in saved.items()}
    snap = None
    token2target, alias = {}, {}
    CHAIN = {'mov','movk','movz','cmp','b.eq','b.ne','csel','adrp','add','b'}
    k = idx[DISPATCH]
    while k < len(insns):
        i = insns[k]
        if i.mnemonic not in CHAIN: break
        m, ops = i.mnemonic, i.operands
        if m == 'cmp' and len(ops) == 2 and ops[1].type == capstone.arm64.ARM64_OP_REG:
            snap = set(regs.get(i.reg_name(ops[1].reg), set()))
        elif m == 'b.eq':
            tgt = parse_int(i.op_str)
            if snap and len(snap) == 1:
                tok = next(iter(snap))
                if tgt == DISPATCH:
                    av = {v for v in regs.get('x9', set()) if isinstance(v, int) and v > 0xFFFF}
                    if len(av) == 1: alias[tok] = next(iter(av))
                else:
                    token2target[tok] = tgt
            snap = None
        elif m == 'b.ne':
            if snap and len(snap) == 1 and k + 1 < len(insns) and insns[k+1].mnemonic == 'b':
                token2target[next(iter(snap))] = parse_int(insns[k+1].op_str)
            snap = None
        sim_step(regs, i)
        k += 1

    block2tok = {}
    for tok, tgt in token2target.items():
        block2tok.setdefault(tgt, tok)

    def resolve(tok, depth=0):
        while tok in alias and depth < 32:
            tok = alias[tok]; depth += 1
        return tok

    # --- block info with rich notes ---
    def block_info(start):
        k = idx.get(start)
        regs = defaultdict(set)
        seq = []
        adrp_reg = {}
        notes = []
        if k is None:
            return set(), [], None, ['unmapped']
        for j in range(k, min(k + 4000, len(insns))):
            i = insns[j]
            seq.append(i)
            m, ops = i.mnemonic, i.operands
            if m == 'adrp' and len(ops) == 2:
                page = ops[1].imm
                if 0x151000 <= page <= 0x156000:
                    adrp_reg[i.reg_name(ops[0].reg)] = page
            elif m == 'add' and len(ops) == 3 and ops[1].type == capstone.arm64.ARM64_OP_REG \
                    and ops[2].type == capstone.arm64.ARM64_OP_IMM:
                r = i.reg_name(ops[1].reg)
                if r in adrp_reg:
                    va = adrp_reg[r] + ops[2].imm
                    if va in strs:
                        key, ln, txt = strs[va]
                        notes.append(f'str@0x{va:x}="{txt[:48]}"')
                    elif 0x155600 <= va < 0x155700:
                        notes.append(f'flag@0x{va:x}')
                    adrp_reg.pop(r)
            elif m == 'bl':
                tgt = parse_int(i.op_str)
                name = e.plt_map.get(tgt)
                notes.append(f'bl {name}' if name else f'bl sub_{tgt:x}')
            elif m == 'b':
                tgt = parse_int(i.op_str)
                if tgt == DISPATCH:
                    nxt = {v for v in regs.get('x9', set()) if isinstance(v, int) and v > 0xFFFF}
                    return nxt, seq, None, notes
                return set(), seq, tgt, notes
            elif m == 'ret':
                return set(), seq, 'ret', notes
            elif m in ('cbz','cbnz','tbz','tbnz'):
                vals = {v for v in regs.get('x9', set()) if isinstance(v, int) and v > 0xFFFF}
                return vals, seq, ('cond', parse_int(i.op_str.split(',')[-1])), notes
            sim_step(regs, i)
        return set(), seq, 'runaway', notes

    # --- DFS ---
    entry = resolve(next(iter(pregss := pregs.get('x9', set())))) if pregs.get('x9') else None
    print(f"entry token -> {hex(entry) if entry else None}")
    seen = set()
    order = []
    def dfs(tok, depth=0):
        if tok in seen or depth > 60:
            return
        seen.add(tok)
        tgt = token2target.get(tok)
        if tgt is None:
            print(f"  tok {hex(tok)} -> NO BLOCK (alias dangling)")
            return
        nxt, seq, exitbr, notes = block_info(tgt)
        order.append(tok)
        ex = '' if exitbr is None else f'  exit={hex(exitbr) if isinstance(exitbr,int) else exitbr}'
        print(f"[{len(order):3d}] tok ..{tok & 0xFFFFFFFFFFFF:010x} blk 0x{tgt:05x} n={len(seq):4d}{ex}")
        if notes:
            for n in notes[:12]:
                print(f"        {n}")
        succs = set()
        for v in nxt:
            succs.add(resolve(v))
        if isinstance(exitbr, int) and exitbr in block2tok:
            succs.add(block2tok[exitbr])
        if isinstance(exitbr, tuple) and exitbr[1] and exitbr[1] in block2tok:
            succs.add(block2tok[exitbr[1]])
        for s in sorted(succs):
            dfs(s, depth + 1)

    dfs(entry)
    print(f"\nvisited {len(order)} blocks; tokens total {len(token2target)}")

if __name__ == '__main__':
    main()
