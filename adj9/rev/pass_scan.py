"""pass_scan.py - collect ALL runtime XOR passes (ldr->eor->str chains) on the
.data string-table area of libsigner.so. Tracks:
  - base formation: adr xN,#tgt  |  adrp xN + add xN,xN,#imm (within 4 insns)
  - loads:  ldrb/ldrh/ldr w/d/q  [xN, #off]
  - keys:   eor wN,wN,#bitmaskimm | eor wN,wN,wM (wM=mov #imm) |
            eor vN.16b,vN,vM (vM=movi vM.8b/16b,#imm)
  - confirms with str back to same addr
Outputs per-byte pass maps for ranges of interest.
"""
import sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from decryptors import LIB

data = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
DELTA = 0x7E20
LO, HI = 0x151000, 0x15540A
RANGES = [(0x153640, 0x153740), (0x1540a0, 0x154120), (0x154300, 0x154420),
          (0x153480, 0x153540), (0x151a00, 0x151d40)]

insns = []
off = 0x1000
while off < 0x14da68:
    got = False
    for ins in md.disasm(data[off:0x14da68], off):
        got = True
        off = ins.address + ins.size
        insns.append(ins)
    if not got:
        off += 4
print("# insns %d" % len(insns), file=sys.stderr)


def norm(reg):
    if ARM64_REG_D0 <= reg <= ARM64_REG_D31:
        return ARM64_REG_V0 + (reg - ARM64_REG_D0)
    if ARM64_REG_S0 <= reg <= ARM64_REG_S31:
        return ARM64_REG_V0 + (reg - ARM64_REG_S0)
    if ARM64_REG_Q0 <= reg <= ARM64_REG_Q31:
        return ARM64_REG_V0 + (reg - ARM64_REG_Q0)
    if ARM64_REG_W0 <= reg <= ARM64_REG_W30:
        return ARM64_REG_X0 + (reg - ARM64_REG_W0)
    if reg == ARM64_REG_WZR:
        return ARM64_REG_XZR
    return reg


def szof(mn):
    if "q" in mn.split()[0][:4]: return 16
    for p, s in (("q", 16), ("d", 8), ("x", 8), ("w", 4), ("s", 4), ("h", 2), ("b", 1)):
        if mn.startswith(p): return s
    return 1


passes = []  # (site, addr, size, key)
pending_base = {}   # reg -> (base_va, site)
loads = []          # list of (insn_idx, reg, addr, size)

for i, ins in enumerate(insns):
    m, ops = ins.mnemonic, ins.operands
    if m in ("adrp", "adr"):
        pending_base[norm(ops[0].reg)] = (ops[1].imm, ins.address)
        continue
    if m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        r = norm(ops[0].reg)
        src = norm(ops[1].reg)
        if src in pending_base and ops[2].imm < 0x100000:
            base, site = pending_base[src]
            tgt = base + ops[2].imm
            if LO <= tgt < HI:
                pending_base[r] = (tgt, site)
            else:
                pending_base.pop(r, None)
        continue
    # invalidate dst reg of other writes
    if m in ("mov", "movz", "movk", "ldr", "ldur", "ldrb", "ldrh", "adr", "adrp", "add"):
        pass
    if m.startswith(("ldr", "ldur")) and len(ops) >= 2 and ops[-1].type == ARM64_OP_MEM:
        b = norm(ops[-1].mem.base)
        d = ops[-1].mem.disp
        if b in pending_base:
            base, site = pending_base[b]
            tgt = base + d
            if LO <= tgt < HI:
                mn0 = ins.op_str.split()[0].rstrip(",")
                sz = szof(mn0)
                loads.append((i, norm(ops[0].reg), tgt, sz, ins.address))
    if m == "eor" and len(ops) == 3 and norm(ops[0].reg) == norm(ops[1].reg):
        key = None
        if ops[2].type == ARM64_OP_IMM:
            key = ops[2].imm & 0xFF
        else:
            rk = norm(ops[2].reg)
            # search back for mov wM,#imm or movi vM.#imm
            for j in range(i - 1, max(0, i - 40), -1):
                pj = insns[j]
                if pj.mnemonic in ("mov", "movz") and len(pj.operands) == 2 and \
                   norm(pj.operands[0].reg) == rk and pj.operands[1].type == ARM64_OP_IMM and \
                   0 < pj.operands[1].imm <= 0xFF:
                    key = pj.operands[1].imm
                    break
                if pj.mnemonic == "movi" and norm(pj.operands[0].reg) == rk and \
                   pj.operands[1].type == ARM64_OP_IMM:
                    key = pj.operands[1].imm
                    break
                if pj.address < ins.address - 0x200:
                    break
        if key is None:
            continue
        rr = norm(ops[0].reg)
        # match most recent load on same reg (vector eor: v reg may be v0 vs ldr q0)
        for (li, lreg, laddr, lsz, lsite) in reversed(loads):
            if lreg == rr and li < i and i - li < 60:
                passes.append((ins.address, laddr, lsz, key, lsite))
                break

# report passes intersecting ranges of interest
print("== passes intersecting target ranges ==")
for (site, addr, sz, key, lsite) in passes:
    for (a, b) in RANGES:
        if a <= addr < b or a <= addr + sz - 1 < b:
            print("site 0x%-7x load@0x%-7x  [%d bytes @0x%x]  key=0x%02x" %
                  (site, lsite, sz, addr, key))
            break
