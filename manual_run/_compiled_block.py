# =============================================================================
# PART 4b -- COMPILED INSTRUCTION FORMS
#
# FAST holds capstone's raw (mnemonic, op_str, next_pc) strings, and the VM
# walked a ~30-deep `elif m == "..."` chain, re-splitting the operand string
# and re-parsing every register name on every one of the ~9.6M steps.  The
# measured execution mix is extremely narrow -- ldr 31%, mov 26%, bl 16%,
# cbnz 15%, everything else 12% -- so each PC is compiled ONCE into an integer
# opcode with fully resolved operand slots and immediates, and FinEx.run
# executes that directly with no string work at all.
#
# Any shape the compiler does not recognise compiles to OC_GEN, which falls
# back to the original string interpreter (kept verbatim as _run_generic).
# Register aliasing is unchanged: an xN write stores 64 bits in RL[n] and the
# low 32 in WL[n]; a wN write stores the zero-extended 32-bit value in both.
# =============================================================================

OC_GEN = 0        # not compiled -- hand back to _run_generic
OC_LD_IMM = 1    # ldr/ldur/ldrb/ldrsw/ldrh...  Rd, [Rn, #off]
OC_ST_IMM = 2    # str/stur/strb                Rs, [Rn, #off]
OC_LD_REGIDX = 3     # ldr Rd, [Rn, Rm{, uxtw #k}]
OC_LD_PAIR = 4       # ldp Rd1, Rd2, [Rn, #off]
OC_ST_PAIR = 5       # stp Rs1, Rs2, [Rn, #off]
OC_LD_POST = 6       # ldr Rd, [Rn], #off
OC_MOV_RR = 7        # mov Rd, Rn
OC_MOV_IMM = 8       # mov Rd, #imm
OC_MOVK = 9          # movk Rd, #imm, lsl #sh
OC_ALU_RR = 10       # Rd = <op> Ra, Rb
OC_ALU_RI = 11       # Rd = <op> Ra, #imm
OC_CMP = 12          # cmp/cmn/tst
OC_BR = 13           # b label
OC_BCOND = 14        # b.<cond> label
OC_CBZ = 15          # cbz/cbnz Rn, label
OC_TB = 16           # tbz/tbnz Rn, #bit, label
OC_CSEL = 17         # csel Rd, Rn, Rm, cond
OC_CSET = 18         # cset Rd, cond
OC_BL = 19           # bl <subroutine>

# ALU sub-ops, ordered by how often they actually execute so the chain that
# picks one stays short.
A_LSR, A_ADD, A_EOR, A_AND, A_LSL, A_SUB, A_ORR, A_MUL = range(8)
_CMP_CMP, _CMP_CMN, _CMP_TST = 0, 1, 2

_LDST = frozenset(("ldr", "ldur", "str", "stur", "ldp", "stp", "ldrsb",
                   "ldrsw", "ldursw", "ldrb", "strb", "ldrsh", "ldrh"))
_ALU = {"add": A_ADD, "sub": A_SUB, "eor": A_EOR, "and": A_AND,
        "orr": A_ORR, "mul": A_MUL, "lsl": A_LSL, "lsr": A_LSR}
_CMPM = {"cmp": _CMP_CMP, "cmn": _CMP_CMN, "tst": _CMP_TST}
_STM = frozenset(("str", "stur", "strb"))


def _ce(s):
    """One operand string -> (kind, slot, is32, imm).
    kind 0 = register, 1 = immediate, 2 = anything else (send to _run_generic)."""
    i = _SLOT.get(s)
    if i is not None:
        return 0, i, s[0] == "w", 0
    if s[:1] == "#":
        return 1, 0, 0, pt(s) or 0
    return 2, 0, 0, 0


def _compile_ldst(m, ops, npc):
    plan = _memplan(m, ops)
    if plan is None:
        return (OC_GEN, npc, m, ops)
    kind = plan[0]
    if kind == "imm":
        _, d, base, off, wb, size, ds, dw, bs, bw = plan
        if wb or ds < 0:            # writeback / exotic name: keep it generic
            return (OC_GEN, npc, m, ops)
        amask = ~7 if size == 8 else ~3
        if m in _STM:
            return (OC_ST_IMM, npc, ds, dw, bs, bw, off, amask)
        sx = 1 if m in ("ldrsw", "ldursw") else (2 if m == "ldrh" else 0)
        return (OC_LD_IMM, npc, ds, dw, bs, bw, off, amask, sx)
    if kind == "pair":
        _, d1, d2, base, off, wb, s1, w1, s2, w2, bs, bw = plan
        if wb or s1 < 0 or s2 < 0 or bs < 0:
            return (OC_GEN, npc, m, ops)
        if m == "stp":
            return (OC_ST_PAIR, npc, s1, w1, s2, w2, bs, bw, off)
        return (OC_LD_PAIR, npc, s1, w1, s2, w2, bs, bw, off)
    if kind == "post":
        _, d, base, imm, ds, dw, bs, bw = plan
        if ds < 0 or bs < 0:
            return (OC_GEN, npc, m, ops)
        return (OC_LD_POST, npc, ds, dw, bs, bw, imm)
    _, d, base, idx, sh, ds, dw, bs, bw, is_, iw = plan
    if ds < 0 or bs < 0 or is_ < 0:
        return (OC_GEN, npc, m, ops)
    return (OC_LD_REGIDX, npc, ds, dw, bs, bw, is_, iw, sh,
            4 if d.startswith("w") else 8)


def _compile(m, ops, npc):
    if m == "bl":
        return (OC_BL, npc, pt(ops))
    if m in _LDST:
        return _compile_ldst(m, ops, npc)
    if m in ("mov", "movz"):
        p = ops.split(",", 1)
        if len(p) != 2:
            return (OC_GEN, npc, m, ops)
        d, s = p[0].strip(), p[1].strip()
        kd, ds, dw, _ = _ce(d)
        if kd:
            return (OC_GEN, npc, m, ops)
        ks, ss, sw, imm = _ce(s)
        if ks == 0:
            return (OC_MOV_RR, npc, ds, dw, ss, sw)
        if ks == 1:
            return (OC_MOV_IMM, npc, ds, dw, imm)
        return (OC_GEN, npc, m, ops)
    if m in _ALU:
        p = _split(ops)
        if len(p) > 3:              # shifted-register form: rare, keep generic
            return (OC_GEN, npc, m, ops)
        ka, as_, aw, aimm = _ce(p[1]) if len(p) > 1 else (2, 0, 0, 0)
        if len(p) > 2:
            kb, bs, bw, bimm = _ce(p[2])
        else:
            kb, bs, bw, bimm = 1, 0, 0, 0
        if ka or kb:
            return (OC_GEN, npc, m, ops)
        kd, ds, dw, _ = _ce(p[0])
        if kd:
            return (OC_GEN, npc, m, ops)
        au = _ALU[m]
        if kb == 0:
            return (OC_ALU_RR, npc, au, ds, dw, as_, aw, bs, bw)
        return (OC_ALU_RI, npc, au, ds, dw, as_, aw, bimm)
    if m in _CMPM:
        p = _split(ops)
        ka, as_, aw, aimm = _ce(p[0]) if p else (2, 0, 0, 0)
        kb, bs, bw, bimm = (_ce(p[1]) if len(p) > 1 else (1, 0, 0, 0))
        if ka or kb:
            return (OC_GEN, npc, m, ops)
        return (OC_CMP, npc, _CMPM[m], aw, as_, aimm, bw, bs, bimm)
    if m == "movk":
        mm = re.match(r"^(\w+),#(0x[0-9a-f]+|\d+)(?:,lsl#(\d+))?", ops.replace(" ", ""))
        if not mm:
            return (OC_GEN, npc, m, ops)
        ds, dw = _SLOT.get(mm.group(1)) or (-1, 0) if False else (None, None)
        i = _SLOT.get(mm.group(1))
        if i is None or mm.group(1)[0] != "x":
            if i is None:
                return (OC_GEN, npc, m, ops)
        sh = int(mm.group(3) or 0)
        keep = (~(0xFFFF << sh)) & (M32 if i is not None and
                                     _SLOT[mm.group(1)] is not None and
                                     mm.group(1)[0] == "w" else M64)
        return (OC_MOVK, npc, i, mm.group(1)[0] == "w", keep,
                (int(mm.group(2), 0) & 0xFFFF) << sh)
    if m == "b":
        t = pt(ops)
        if t is None:
            return (OC_GEN, npc, m, ops)
        return (OC_BR, npc, t, t == 0x100318)
    if m[:2] == "b." and len(m) > 2:
        t = pt(ops)
        if t is None:
            return (OC_GEN, npc, m, ops)
        return (OC_BCOND, npc, m[2:], t, t == 0x100318)
    if m == "cbz" or m == "cbnz":
        p = _split(ops)
        if len(p) != 2:
            return (OC_GEN, npc, m, ops)
        k, s, isw, _ = _ce(p[0])
        t = pt(p[1])
        if k or t is None:
            return (OC_GEN, npc, m, ops)
        return (OC_CBZ, npc, m == "cbnz", s, isw, t, t == 0x100318)
    if m == "tbz" or m == "tbnz":
        p = _split(ops)
        if len(p) != 3:
            return (OC_GEN, npc, m, ops)
        k, s, isw, _ = _ce(p[0])
        t = pt(p[2])
        bit = pt(p[1])
        if k or t is None or bit is None:
            return (OC_GEN, npc, m, ops)
        return (OC_TB, npc, m == "tbnz", s, isw, bit, t, t == 0x100318)
    if m == "csel":
        p = _split(ops)
        if len(p) != 4:
            return (OC_GEN, npc, m, ops)
        kd, ds, dw, _ = _ce(p[0])
        k1, s1, w1, _ = _ce(p[1])
        k2, s2, w2, _ = _ce(p[2])
        if kd or k1 or k2:
            return (OC_GEN, npc, m, ops)
        return (OC_CSEL, npc, ds, dw, s1, w1, s2, w2, p[3])
    if m == "cset":
        p = _split(ops)
        if len(p) != 2:
            return (OC_GEN, npc, m, ops)
        kd, ds, dw, _ = _ce(p[0])
        if kd:
            return (OC_GEN, npc, m, ops)
        return (OC_CSET, npc, ds, dw, p[1])
    return (OC_GEN, npc, m, ops)


CFPC = {}                      # pc -> compiled form


def _build_cf():
    CFPC.clear()
    for pc, k in IDX.items():
        m, ops, npc = FAST[k]
        CFPC[pc] = _compile(m, ops, npc)


