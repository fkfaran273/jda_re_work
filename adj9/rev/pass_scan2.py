"""pass_scan2.py - exhaustive pass enumeration for given byte ranges.
Catches BOTH key forms: eor with w-reg immediate key, and eor vN.8b,vN,vM (vector,
key = current value of vM - unknown, needs manual/brute resolution).
Only trusts base formation via `adr` exact or adrp+add within 2 insns.
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
RANGES = [(0x153640, 0x153740), (0x1540a0, 0x154120), (0x154300, 0x154420)]

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


def szof(mn0):
    for p, s in (("q", 16), ("d", 8), ("x", 8), ("w", 4), ("s", 4), ("h", 2), ("b", 1)):
        if mn0.startswith(p):
            return s
    return 1


def in_ranges(a):
    return any(lo <= a < hi for (lo, hi) in RANGES)


hits = []
for i, ins in enumerate(insns):
    m, ops = ins.mnemonic, ins.operands
    # base formation
    base = None
    if m == "adr":
        base = (norm(ops[0].reg), ops[1].imm, i)
    elif m == "adrp" and i + 1 < len(insns):
        n1 = insns[i + 1]
        if n1.mnemonic == "add" and len(n1.operands) == 3 and \
           n1.operands[1].type == ARM64_OP_REG and norm(n1.operands[1].reg) == norm(ops[0].reg) and \
           n1.operands[2].type == ARM64_OP_IMM:
            base = (norm(n1.operands[0].reg), ops[1].imm + n1.operands[2].imm, i + 1)
    if base is None:
        continue
    breg, bva, bidx = base
    # loads from this base within next 30 insns
    for j in range(i + 1, min(i + 31, len(insns))):
        lj = insns[j]
        if lj.mnemonic in ("adrp", "adr"):
            break
        if lj.mnemonic.startswith(("ldr", "ldur")) and len(lj.operands) >= 2 and \
           lj.operands[-1].type == ARM64_OP_MEM and norm(lj.operands[-1].mem.base) == breg:
            tgt = bva + lj.operands[-1].mem.disp
            mn0 = lj.op_str.split()[0].rstrip(",")
            sz = szof(mn0)
            if in_ranges(tgt) or in_ranges(tgt + sz - 1):
                lreg = norm(lj.operands[0].reg)
                # find eor consuming lreg within 25 insns
                for k in range(j + 1, min(j + 26, len(insns))):
                    ek = insns[k]
                    if ek.mnemonic == "eor" and len(ek.operands) == 3 and \
                       norm(ek.operands[0].reg) == lreg and norm(ek.operands[1].reg) == lreg:
                        if ek.operands[2].type == ARM64_OP_IMM:
                            key = "0x%02x" % (ek.operands[2].imm & 0xFF)
                        else:
                            kr = ins.reg_name(ek.operands[2].reg)
                            key = "v?%s" % kr
                        hits.append((ek.address, tgt, sz, key, lj.address))
                        break
                    if ek.mnemonic.startswith(("ldr", "mov", "str")) and \
                       norm(ek.operands[0].reg) == lreg and ek.address != lj.address:
                        break
    # ldrb/strb byte-loop blocks are covered by the same walk (ldrb is a ldr)

seen = set()
for (site, tgt, sz, key, lsite) in hits:
    tag = (site, tgt, sz)
    if tag in seen:
        continue
    seen.add(tag)
    print("eor@0x%-7x load@0x%-7x range 0x%x..0x%x (%dB) key=%s" %
          (site, lsite, tgt, tgt + sz - 1, sz, key))
