"""symtrack.py v2 - symbolic pointer+value tracking over a flattened function.
Seeds x29=base; tracks arg regs (x0-x7) symbolically through moves/adds and
stack spill slots; reports memory accesses whose ADDRESS derives from args,
and stores of arg-derived pointers to stack slots.
Usage: symtrack.py <start_va> <count>
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from decryptors import LIB

START = int(sys.argv[1], 16)
N = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
data = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

ARGREGS = {ARM64_REG_X0: 0, ARM64_REG_X1: 1, ARM64_REG_X2: 2, ARM64_REG_X3: 3,
           ARM64_REG_X4: 4, ARM64_REG_X5: 5, ARM64_REG_X6: 6, ARM64_REG_X7: 7}

def expr_str(e):
    if e is None: return "?"
    t = e[0]
    if t == "arg": return "arg%d" % e[1]
    if t == "x29": return "x29%+#x" % e[1]
    if t == "sp": return "sp%+#x" % e[1]
    if t == "lit": return "lit:0x%x" % e[1]
    if t == "add": return "(%s%+#x)" % (expr_str(e[1]), e[2])
    return "?"

def arg_of(e):
    if e is None: return None
    if e[0] == "arg": return e[1]
    if e[0] == "add": return arg_of(e[1])
    return None

def flat(e):
    # collapse ('add', x, d) chains to (root, total_delta)
    if e is None: return (None, 0)
    if e[0] in ("arg", "x29", "sp", "lit"): return (e, 0)
    if e[0] == "add":
        r, d = flat(e[1])
        return (r, d + e[2])
    return (None, 0)

reg = {}
slot = {}  # (root_id, delta) -> expr  for x29/sp slots

def slotkey(e):
    r, d = flat(e)
    if r and r[0] in ("x29", "sp"):
        return (r[0], d)
    return None

reg[ARM64_REG_X29] = ("x29", 0)
reg[ARM64_REG_SP] = ("x29", -0x80)  # approximation, refined by prologue subs
for r, k in ARGREGS.items():
    reg[r] = ("arg", k)

def memexpr(op):
    if op.type != ARM64_OP_MEM: return None
    b = op.mem.base
    if b == 0: return None
    if b == ARM64_REG_X29: return ("x29", op.mem.disp)
    if b == ARM64_REG_SP: return ("sp", op.mem.disp)
    return reg.get(b)

insns = list(md.disasm(data[START:START + N * 4], START))[:N]
for ins in insns:
    m, ops = ins.mnemonic, ins.operands
    wregs = []
    if m in ("adrp", "adr"):
        reg[ops[0].reg] = ("lit", ops[1].imm); continue
    if m == "mov" and len(ops) == 2 and ops[1].type == ARM64_OP_REG:
        reg[ops[0].reg] = reg.get(ops[1].reg); continue
    if m in ("movz", "mov") and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
        reg.pop(ops[0].reg, None); continue
    if m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        src = reg.get(ops[1].reg)
        reg[ops[0].reg] = ("add", src, ops[2].imm) if src else None
        continue
    if m == "sub" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        src = reg.get(ops[1].reg)
        reg[ops[0].reg] = ("add", src, -ops[2].imm) if src else None
        continue
    if m in ("ldr", "ldur", "ldrb", "ldursb", "ldrsw", "ldrh"):
        e = memexpr(ops[1])
        sk = slotkey(e)
        if sk and sk in slot:
            reg[ops[0].reg] = slot[sk]
        elif arg_of(e) is not None:
            reg[ops[0].reg] = e
        else:
            reg.pop(ops[0].reg, None)
        continue
    if m in ("str", "stur", "strb", "strh"):
        e = memexpr(ops[1]); val = reg.get(ops[0].reg)
        sk = slotkey(e)
        if sk:
            slot[sk] = val
        a = arg_of(e)
        if a is not None:
            r, d = flat(e)
            print("ARGSTORE 0x%x  %s %s   addr=%s" % (ins.address, m, ins.op_str, expr_str(e)))
        continue
    if m in ("stp", "ldp"):
        e = memexpr(ops[2])
        if m == "stp":
            sk = slotkey(e)
            if sk:
                slot[sk] = reg.get(ops[0].reg)
                slot[(sk[0], sk[1] + 8)] = reg.get(ops[1].reg)
            if arg_of(e) is not None:
                print("ARGSTORE 0x%x  %s %s   addr=%s" % (ins.address, m, ins.op_str, expr_str(e)))
        else:
            sk = slotkey(e)
            reg[ops[0].reg] = slot.get(sk) if sk else None
            reg[ops[1].reg] = slot.get((sk[0], sk[1] + 8)) if sk else None
        continue
    # any other instruction: clobber written regs
    try:
        w = set(ins.regs_access()[1])
    except Exception:
        w = set()
    for r in w:
        reg.pop(r, None)
print("# done")
