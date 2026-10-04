"""Un-flatten the O-LLVM dispatcher at 0x24a40 in libsigner.so.

Model (confirmed by disassembly):
  head 0x24a40:  mov x8, x9 ; chain of { [token mat] cmp x8, (reg) ; b.eq T }
    - T == work block  -> real transition
    - T == 0x24a40     -> alias: state := token materialized in the other reg; loop
  work block: ... ; materialize next token in x9 (maybe csel between two) ; b 0x24a40
  callee-saved regs (x9..x15, x19..x28) hold tokens loaded in the prologue.
"""
import sys, json
from collections import defaultdict
import capstone

sys.path.insert(0, '.')
from elf import ELF
from decryptors import LIB

DISPATCH = 0x24A40
CHAIN_OPS = {'mov', 'movk', 'movz', 'cmp', 'b.eq', 'b.ne', 'csel', 'adrp', 'add', 'b'}


def sim_step(regs, i):
    """Advance the constant-tracking sim by one instruction."""
    m, ops = i.mnemonic, i.operands
    if m == 'mov' and len(ops) == 2 and ops[0].type == capstone.arm64.ARM64_OP_REG:
        d = i.reg_name(ops[0].reg)
        if ops[1].type == capstone.arm64.ARM64_OP_IMM:
            regs[d] = {ops[1].imm & 0xFFFFFFFFFFFFFFFF}
        elif ops[1].type == capstone.arm64.ARM64_OP_REG:
            regs[d] = set(regs.get(i.reg_name(ops[1].reg), set()))
        else:
            regs[d] = set()
    elif m in ('movz', 'movk') and len(ops) == 2 and ops[1].type == capstone.arm64.ARM64_OP_IMM:
        d = i.reg_name(ops[0].reg)
        sh = ops[1].shift.value if ops[1].shift.type else 0
        part = (ops[1].imm & 0xFFFF) << sh
        if m == 'movz':
            regs[d] = {part}
        else:
            regs[d] = {(v & ~(0xFFFF << sh)) | part for v in (regs.get(d) or {0})}
    elif m == 'csel':
        parts = [p.strip() for p in i.op_str.split(',')]
        if len(parts) >= 3:
            d, a, b = parts[0], parts[1], parts[2]
            regs[d] = set(regs.get(a, set())) | set(regs.get(b, set()))


def parse_int(s):
    try:
        return int(s.strip().lstrip('#'), 16)
    except (ValueError, AttributeError):
        return None


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); md.detail = True
    t = e.byname['.text']; off0 = e.vaddr_to_off(t['addr'])
    insns = list(md.disasm(e.data[off0:off0 + t['size']], t['addr']))
    idx = {i.address: k for k, i in enumerate(insns)}

    # ---- 1. owning function prologue -> token registers
    fn_start = None
    for k in range(idx[DISPATCH], 0, -1):
        i = insns[k]
        if i.mnemonic == 'paciasp' or (i.mnemonic == 'stp' and i.op_str.startswith('x29, x30')):
            fn_start = i.address
            break
    print(f"dispatcher owner fn starts at 0x{fn_start:x}")
    pregs = defaultdict(set)
    for i in insns[idx[fn_start]:idx[DISPATCH]]:
        sim_step(pregs, i)
    saved = {r: next(iter(v)) for r, v in pregs.items()
             if r.startswith('x') and len(v) == 1 and next(iter(v)) > 0xFFFF}
    print("token regs:", {r: hex(v) for r, v in sorted(saved.items())})

    # ---- 2. parse dispatcher chain
    token2target, alias = {}, {}
    regs = {r: {v} for r, v in saved.items()}
    regs['x8'] = {'STATE'}          # incoming state: unknown
    snap = None
    n_unres = 0
    k = idx[DISPATCH]
    while k < len(insns):
        i = insns[k]
        if i.mnemonic not in CHAIN_OPS:
            break
        m, ops = i.mnemonic, i.operands
        if m == 'cmp' and len(ops) == 2 and ops[1].type == capstone.arm64.ARM64_OP_REG:
            snap = set(regs.get(i.reg_name(ops[1].reg), set()))
        elif m == 'b.eq':
            tgt = parse_int(i.op_str)
            if snap and len(snap) == 1:
                tok = next(iter(snap))
                if tgt == DISPATCH:
                    av = {v for v in regs.get('x9', set()) if v != 'STATE'}
                    if len(av) == 1:
                        alias[tok] = next(iter(av))
                    else:
                        n_unres += 1
                else:
                    token2target[tok] = tgt
            else:
                n_unres += 1
            snap = None
        elif m == 'b.ne':
            if snap and len(snap) == 1 and k + 1 < len(insns) and insns[k + 1].mnemonic == 'b':
                token2target[next(iter(snap))] = parse_int(insns[k + 1].op_str)
            snap = None
        elif m == 'b' and m == 'b' and k > idx[DISPATCH] + 8 and parse_int(i.op_str) == fn_start:
            break
        sim_step(regs, i)
        k += 1
    print(f"chain parsed {k - idx[DISPATCH]} insns -> {len(token2target)} real, "
          f"{len(alias)} alias, {n_unres} unresolved")

    def resolve(tok, depth=0):
        while tok in alias and depth < 16:
            tok = alias[tok]; depth += 1
        return tok

    # ---- 3. simulate each real block: find its exit and next token(s)
    block2tok = {}
    for tok, tgt in token2target.items():
        block2tok.setdefault(tgt, tok)

    def block_info(start):
        k = idx.get(start)
        if k is None:
            return set(), [], None
        regs = defaultdict(set)
        seq = []
        for j in range(k, min(k + 4000, len(insns))):
            i = insns[j]
            seq.append(i)
            m = i.mnemonic
            if m == 'b':
                tgt = parse_int(i.op_str)
                if tgt == DISPATCH:
                    return {v for v in regs.get('x9', set()) if isinstance(v, int) and v >= (1 << 32)}, seq, None
                return set(), seq, tgt
            if m == 'ret':
                return set(), seq, 'ret'
            if m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                vals = {v for v in regs.get('x9', set()) if isinstance(v, int) and v >= (1 << 32)}
                return vals, seq, ('cond', parse_int(i.op_str.split(',')[-1]))
            sim_step(regs, i)
        return set(), seq, 'runaway'

    edges = {}
    for tok, tgt in sorted(token2target.items()):
        nxt, seq, exitbr = block_info(tgt)
        if isinstance(exitbr, int) and exitbr in block2tok:
            nxt = {block2tok[exitbr]}
        edges[tok] = (tgt, nxt, exitbr, seq)

    # ---- 4. walk from the entry token
    init = pregs.get('x9', set())
    print(f"\nentry token: {[hex(v) for v in init]}")
    out = {'tokens': {hex(a): hex(b) for a, b in token2target.items()},
           'alias': {hex(a): hex(b) for a, b in alias.items()},
           'saved': {r: hex(v) for r, v in saved.items()},
           'edges': {hex(t): [hex(g), sorted(hex(x) for x in n),
                              hex(e) if isinstance(e, int) else str(e)]
                     for t, (g, n, e, _) in edges.items()}}
    json.dump(out, open('unflatten_map.json', 'w'), indent=1)

    print("\n=== execution walk ===")
    cur = resolve(next(iter(init))) if init else None
    seen = set()
    hops = 0
    while cur is not None and cur in edges and hops < 500:
        if cur in seen:
            print(f"  [cycle — machine loops back to 0x{edges[cur][0]:x}]")
            break
        seen.add(cur)
        tgt, nxt, exitbr, seq = edges[cur]
        notes = []
        for i in seq:
            if i.mnemonic == 'bl':
                notes.append(f"bl {i.op_str}")
            elif i.mnemonic in ('stlrb',) or (i.mnemonic == 'ldrb' and '0x8f' in i.op_str) \
                    or (i.mnemonic == 'strb' and '0x8f' in i.op_str) \
                    or (i.mnemonic == 'adrp' and '#0x15' in i.op_str):
                notes.append(f"{i.mnemonic} {i.op_str}")
        ex = '' if exitbr is None else f' exit={hex(exitbr) if isinstance(exitbr, int) else exitbr}'
        print(f"tok ..{cur & 0xFFFFFFFFFFFF:012x} -> blk 0x{tgt:05x} n={len(seq):4d} "
              f"next={sorted(hex(x) for x in nxt)}{ex}")
        if notes:
            print(f"        {'; '.join(notes[:8])}")
        if len(nxt) == 1:
            cur = resolve(next(iter(nxt)))
        elif len(nxt) == 0 and isinstance(exitbr, int) and exitbr in block2tok:
            cur = block2tok[exitbr]
        else:
            print("  [conditional/terminal — stopping linear walk]")
            break
        hops += 1


if __name__ == '__main__':
    main()
