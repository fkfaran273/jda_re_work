"""_inv2_dis.py — disassemble the diagonal-2 sites from libsigner.so."""
import sys
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB

elf = open(LIB, "rb").read()

# vaddr -> file offset: scan PT_LOAD via simple mapping used by vm_final
try:
    from elf import ELF as _ELF
    e = _ELF(LIB)
    v2o = e.vaddr_to_off
except Exception:
    v2o = None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

SITES = [(0x10d0ec, 0x60), (0x110e30, 0x60), (0x10a5fc, 0x60), (0x10fbf4, 0x60)]
for (va, n) in SITES:
    print("==== site %#x ====" % va)
    off = v2o(va)
    for i in md.disasm(elf[off:off + n], va):
        print("  %#x: %-8s %s" % (i.address, i.mnemonic, i.op_str))
