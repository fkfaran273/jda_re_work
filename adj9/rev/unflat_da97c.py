"""unflat_da97c.py - mechanical unflatten of O-LLVM flattened machines (fixed engine).

Model (matches 0xda97c..0xdb1cb, hub head 0xdaad0): work blocks materialize the next
64-bit tag into the SOURCE register (x9) by mov+movk chains and `b` the hub head; the
hub head does `mov x8, x9` (consume pipeline) then reloads x9 with a fixed constant
interleaved with the cmp x8,<reg>; b.eq chain. Successor of any transition through the
hub head = the value of x9 AT THE MOMENT OF ARRIVAL. Comparands are materialized in
the prologue (callee-saved regs) and inline in the chain. csel into x9 gives two
candidate successors; ldr x9,[sp,#off] is resolved through a spill table built by the
prologue simulation (csel'd config tags live there).

Entry-tag fix (was the empty-DFS bug): the old code scanned prologue..HUB for x8/x9
materializations and only caught a PARTIAL movk chain (low 32 bits 0xd72bcdf8 of the
real tag). Now: find the function entry (unique external bl/b into the range), simulate
the prologue linearly to the hub head, and take the value of the SOURCE register there
= real entry tag. DFS follows block exits (x9 at block end, pairs for csel, RET for
epilogue).

Usage: python unflat_da97c.py [start_va_hex end_va_hex hub_va]
"""
import sys, os, re
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import scan_rand as S

LO, HI = 0xda97c, 0xdb1cc
HUB = 0xdaadc          # first cmp of the hub chain
HUB_HEAD = 0xdaad0     # b target that re-enters dispatch (mov x8, x9)
if len(sys.argv) > 3:
    LO, HI, HUB = int(sys.argv[1], 16), int(sys.argv[2], 16), int(sys.argv[3], 16)
    HUB_HEAD = None      # auto-detect below

INS = [x for x in S.INSNS if LO <= x[0] < HI]
BY = {a: i for i, (a, m, o) in enumerate(INS)}
IDXG = S.IDX

RE_MOV_IMM = re.compile(r'^(x\d+), #(0x[0-9a-f]+)$')
RE_MOVK = re.compile(r'^(x\d+), #(0x[0-9a-f]+), lsl #(\d+)$')
RE_MOV_REG = re.compile(r'^(x\d+), (x\d+)$')
RE_CSEL = re.compile(r'^(x\d+), (x\d+), (x\d+), \w+$')
RE_LDR_SP = re.compile(r'^(x\d+), \[sp(?:, #(0x[0-9a-f]+|\d+))?\]$')
RE_STR_SP = re.compile(r'^(x\d+), \[sp(?:, #(0x[0-9a-f]+|\d+))?\]$')
RE_ADD_SP = re.compile(r'^(x\d+), sp(?:, #(0x[0-9a-f]+|\d+))?$')
RE_LDR_BASE = re.compile(r'^(x\d+), \[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]$')


def offv(tok):
    if tok is None:
        return 0
    return int(tok, 16) if tok.startswith('0x') else int(tok)


def ptarget(op):
    try:
        return int(op.replace('#', ''), 16)
    except ValueError:
        return None


def find_fn_entry():
    """function entry = target of the unique branch from OUTSIDE [LO,HI)."""
    cands = {}
    for a, m, o in S.INSNS:
        if m in ('bl', 'b') and o.startswith('#'):
            t = ptarget(o)
            if t is not None and LO <= t < HI and not (LO <= a < HI):
                cands.setdefault(t, []).append(a)
    if cands:
        e = min(cands)  # lowest external landing = prologue
        return e, cands
    return LO, cands


def step(a, m, o, regs, mem):
    """simulate one instruction; returns 'exit' kind or None.
    regs: reg -> int | ('pair', v1, v2) | ('mem', spoff) | ('base', off) | None
    mem : sp-offset -> value"""
    mm = RE_MOV_IMM.match(o)
    if m == 'mov' and mm:
        regs[mm.group(1)] = int(mm.group(2), 16) & 0xFFFFFFFFFFFFFFFF
        return None
    mk = RE_MOVK.match(o)
    if m == 'movk' and mk:
        r = mk.group(1)
        cur = regs.get(r)
        if isinstance(cur, int):
            regs[r] = cur | ((int(mk.group(2), 16) & 0xFFFF) << int(mk.group(3)))
        else:
            regs[r] = None  # movk over non-int -> unknown
        return None
    mv = RE_MOV_REG.match(o)
    if m == 'mov' and mv:
        d, sr = mv.group(1), mv.group(2)
        v = regs.get(sr)
        regs[d] = ('same',) if sr == 'x8' and v == 'SAME8' else v
        return None
    cs = RE_CSEL.match(o)
    if m == 'csel' and cs:
        d, A, B = cs.group(1), cs.group(2), cs.group(3)
        va, vb = regs.get(A), regs.get(B)
        if isinstance(va, int) and isinstance(vb, int):
            regs[d] = ('pair', va, vb)
        else:
            regs[d] = va if va is not None else vb
        return None
    ld = RE_LDR_SP.match(o)
    if m in ('ldr', 'ldur') and ld:
        d = ld.group(1)
        off = offv(ld.group(2))
        regs[d] = mem.get(off)  # None if not tracked
        return None
    st = RE_STR_SP.match(o)
    if m in ('str', 'stur') and st:
        sr = st.group(1)
        off = offv(st.group(2))
        if sr in regs and regs[sr] is not None:
            mem[off] = regs[sr]
        return None
    ad = RE_ADD_SP.match(o)
    if m == 'add' and ad:
        regs[ad.group(1)] = ('base', offv(ad.group(2)))
        return None
    lb = RE_LDR_BASE.match(o)
    if m in ('ldr', 'ldur') and lb:
        d, b, off = lb.group(1), lb.group(2), offv(lb.group(3))
        base = regs.get(b)
        if isinstance(base, tuple) and base[0] == 'base':
            regs[d] = mem.get(base[1] + off)  # region reads: unknown unless spilled
        else:
            regs[d] = None
        return None
    if m in ('str',) and lb:
        return None
    if m == 'bl':
        # calls clobber caller-saved x0-x18 EXCEPT keep it simple: we only trust
        # values written AFTER the last bl in a block; clobber x0-x17.
        for r in ['x%d' % i for i in range(0, 18)]:
            if r in regs:
                regs[r] = None
        return None
    return None


def sim_range(i0, i1, regs, mem, stop_at_b=True):
    """simulate INS[i0:i1); return ('b',tgt) ('b.cond',tgt,cc) ('ret',) or ('end',)."""
    for i in range(i0, i1):
        a, m, o = INS[i]
        if m == 'b' and o.startswith('#'):
            return ('b', ptarget(o), a)
        if m in ('b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
                 'b.hi', 'b.ls', 'b.ge', 'cbz', 'cbnz', 'tbz', 'tbnz') :
            t = ptarget(o)
            if t is not None:
                return ('b.cond', t, a, m)
        if m == 'ret':
            return ('ret', None, a)
        if m in ('br', 'blr'):
            return ('ret', None, a)
        step(a, m, o, regs, mem)
    return ('end', None, None)


def block_exit(bva):
    """successor tag(s) of work block starting at bva: value of SRC reg at hub arrival."""
    regs = dict(PROLOGUE_REGS)
    mem = dict(PROLOGUE_MEM)
    i = BY[bva]
    kind, tgt, a = sim_range(i, len(INS), regs, mem)
    if kind == 'b' and tgt is not None and LO <= tgt < HI:
        if tgt == HUB_HEAD:
            v = regs.get(SRC)
            return resolve(v, mem), 'b hub', a
        if tgt in BY:  # jump to another block in range: adopt its exit
            v2, how, a2 = block_exit(tgt)
            return v2, 'b 0x%x->%s' % (tgt, how), a2
        return None, 'b 0x%x' % tgt, a
    if kind == 'b.cond':
        v = resolve(regs.get(SRC), mem)
        return v, '%s 0x%x' % (kind if len(kind) == 2 else kind, tgt), a
    if kind == 'ret':
        return 'RET', 'ret', a
    return None, kind, a


def resolve(v, mem):
    if isinstance(v, tuple) and v and v[0] == 'mem':
        return mem.get(v[1], ('mem', v[1]))
    return v


def parse_chain():
    """walk the hub chain; return tab: tag -> (target, x9val_at_site, cmp_site)."""
    regs = dict(PROLOGUE_REGS)
    mem = dict(PROLOGUE_MEM)
    tab = {}
    i = BY[HUB_HEAD]
    a, m, o = INS[i]
    step(a, m, o, regs, mem)          # mov x8, x9  (x8 = entry tag)
    state_at_head = regs.get('x8')
    j = i + 1
    last_cmp = None
    while j < len(INS):
        a, m, o = INS[j]
        if m == 'cmp':
            cm = re.match(r'^(x\d+), (x\d+)$', o)
            if cm and cm.group(1) == STATE:
                last_cmp = (cm.group(2), j)
            j += 1
            continue
        if m == 'b.eq' and last_cmp:
            t = ptarget(o)
            cr, cj = last_cmp
            val = resolve(regs.get(cr), mem)
            last_cmp = None
            if isinstance(val, int):
                tab[val] = (t, regs.get(SRC), cj)
            elif isinstance(val, tuple) and val and val[0] == 'pair':
                for v in val[1:]:
                    tab[v] = (t, regs.get(SRC), cj)
            j += 1
            continue
        if m in ('b.ne',) and last_cmp:
            # default path (conduit): x9 may hold a reloaded/spilled value
            t = ptarget(o)
            cr, cj = last_cmp
            last_cmp = None
            j += 1
            continue
        if m == 'b' and o.startswith('#'):
            t = ptarget(o)
            if t is None or not (LO <= t < HI):
                break
            j = BY[t]
            continue
        if m == 'ret':
            break
        step(a, m, o, regs, mem)
        j += 1
    return tab, state_at_head


def bl_summary(bva, endva):
    out = []
    for a, m, o in INS[BY[bva]:BY[endva] + 1 if endva in BY else len(INS)]:
        if m == 'bl' and o.startswith('#'):
            t = ptarget(o)
            out.append('0x%x bl 0x%x %s' % (a, t, S.PLT.get(t, '')))
    return out


def main():
    global HUB_HEAD, STATE, SRC, PROLOGUE_REGS, PROLOGUE_MEM
    fn_entry, cands = find_fn_entry()
    print("external branches into range: %s" %
          {hex(k): [hex(x) for x in v] for k, v in cands.items()})
    print("function entry (prologue): 0x%x" % fn_entry)
    if HUB_HEAD is None:
        # hub head = 'mov x8, x9' style: find b target named by work blocks; fallback HUB-8
        HUB_HEAD = HUB
    # detect STATE/SRC from hub head + first cmp
    i = BY[HUB_HEAD]
    mv = RE_MOV_REG.match(INS[i][2])
    if INS[i][1] == 'mov' and mv:
        SRC = mv.group(2)
        STATE = mv.group(1)
    else:
        SRC, STATE = 'x9', 'x8'
    # first cmp operand in chain
    for k in range(BY[HUB], min(BY[HUB] + 8, len(INS))):
        if INS[k][1] == 'cmp':
            cm = re.match(r'^(x\d+), (x\d+)$', INS[k][2])
            if cm:
                STATE = cm.group(1)
                break
    print("STATE=%s SRC=%s HUB_HEAD=0x%x" % (STATE, SRC, HUB_HEAD))

    # prologue simulation: fn_entry .. HUB_HEAD
    PROLOGUE_REGS, PROLOGUE_MEM = {}, {}
    sim_range(BY[fn_entry], BY[HUB_HEAD], PROLOGUE_REGS, PROLOGUE_MEM)
    entry_tag = PROLOGUE_REGS.get(SRC)
    print("prologue regs with 64-bit materializations:")
    for r, v in sorted(PROLOGUE_REGS.items()):
        if isinstance(v, int):
            print("  %s = %016x" % (r, v))
    print("prologue spills: %s" % {hex(k): ('pair' if isinstance(v, tuple) and v[0] == 'pair' else v)
                                    for k, v in sorted(PROLOGUE_MEM.items())})
    print("ENTRY TAG: %s" % (("%016x" % entry_tag) if isinstance(entry_tag, int) else entry_tag))

    tab, state_at_head = parse_chain()
    print("hub: %d tags resolved" % len(tab))
    for v in sorted(tab):
        t, x9v, cj = tab[v]
        print("  tag %016x -> block 0x%x (cmp@0x%x)" % (v, t, cj))

    # DFS
    print("\nDFS from entry (execution order):")
    seen, order = set(), []
    stack = [entry_tag if isinstance(entry_tag, int) else None]
    edges = {}
    while stack:
        v = stack.pop()
        if v is None or v == 'RET' or v in seen:
            continue
        seen.add(v)
        order.append(v)
        e = tab.get(v)
        if e is None:
            print("  tag %016x -> NOT IN HUB (stop)" % v)
            continue
        t, x9v, cj = e
        if t == HUB_HEAD:
            nv = resolve(x9v, PROLOGUE_MEM)
            how = 'via hub head (x9@0x%x)' % cj
            enda = cj
        else:
            nv, how, enda = block_exit(t)
        edges[v] = (t, nv, how, enda)
        if isinstance(nv, tuple) and nv and nv[0] == 'pair':
            for c in reversed(nv[1:]):
                stack.append(c)
        elif isinstance(nv, int):
            stack.append(nv)
    for v in order:
        if v not in edges:
            print("  tag %016x -> UNPARSED EXIT (leaf)" % v)
            continue
        t, nv, how, enda = edges[v]
        nvs = ("%016x" % nv) if isinstance(nv, int) else (
            'pair(%s | %s)' % tuple('%016x' % c for c in nv[1:]) if isinstance(nv, tuple) and nv and nv[0] == 'pair' else str(nv))
        print("  tag %016x block 0x%x -> %s   [%s]" % (v, t, nvs, how))
        for bl in bl_summary(t, enda):
            print("        %s" % bl)
    # landmark check
    for landmark in (0xdafe4,):
        for v, (t, nv, how, enda) in edges.items():
            if t <= landmark <= max(enda or t, t + 0x400):
                print("\n*** landmark 0x%x inside block 0x%x (tag %016x) - reachable" % (landmark, t, v))


if __name__ == '__main__':
    main()
