"""scan_refs.py - linear disasm of libsigner.so .text; find:
  1. bl sites to target VAs
  2. str/ldr with given immediates (region offsets)
  3. adrp(+add)/adr-formed global references to given addresses
Usage: scan_refs.py <bltargets_csv|-> <offsets_csv|-> <globals_csv|->
"""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from decryptors import LIB

def arglist(s):
    return [int(t, 16) for t in s.split(",")] if s and s != "-" else []

BL_TARGETS = arglist(sys.argv[1] if len(sys.argv) > 1 else "-")
OFFS = arglist(sys.argv[2] if len(sys.argv) > 2 else "-")
GLOBALS = arglist(sys.argv[3] if len(sys.argv) > 3 else "-")

data = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

TEXT_LO, TEXT_HI = 0x1000, 0x150000
page = {}  # reg id -> absolute address formed by adrp/adr/add

def wregs(ins):
    r, w = ins.regs_access()
    return set(w)

# robust linear sweep: restart at next word after undecodable bytes
def sweep():
    off = TEXT_LO
    while off < TEXT_HI:
        got = False
        for ins in md.disasm(data[off:TEXT_HI], off):
            got = True
            yield ins
            off = ins.address + ins.size
        if not got:
            off += 4

for ins in sweep():
    m, ops = ins.mnemonic, ins.operands
    w = wregs(ins)
    # drop stale tracking for written regs first (except the instruction that forms it)
    for r in w:
        if not (m in ("adrp", "adr", "add") and r == ops[0].reg):
            page.pop(r, None)
    if m == "adrp":
        page[ops[0].reg] = ops[1].imm
    elif m == "adr":
        page[ops[0].reg] = ops[1].imm
    elif m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        if ops[1].reg in page:
            page[ops[0].reg] = page[ops[1].reg] + ops[2].imm
    elif m.startswith("ldr") or m.startswith("str") or m in ("stp", "ldp", "ldnp", "stnp", "cas", "casa", "casl", "casal", "swp"):
        # find MEM operand at any index
        for k, o in enumerate(ops):
            if o.type == ARM64_OP_MEM:
                base_r = o.mem.base
                imm = o.mem.disp
                if base_r in page:
                    addr = page[base_r] + imm
                    if addr in GLOBALS:
                        print("GREF  0x%-8x %s %s" % (ins.address, m, ins.op_str))
                if OFFS and imm in OFFS:
                    formed = ("@0x%x" % (page[base_r] + imm)) if base_r in page else ""
                    print("ROFFS 0x%-8x %s %s %s" % (ins.address, m, ins.op_str, formed))
                break
    elif m == "bl":
        if ops and ops[0].type == ARM64_OP_IMM and ops[0].imm in BL_TARGETS:
            print("CALL  0x%-8x bl 0x%x" % (ins.address, ops[0].imm))
