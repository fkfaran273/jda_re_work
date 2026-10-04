"""Disassemble libsigner.so native code around the region materializer.

vaddr == file offset for the first PT_LOAD (verified in prior work).
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SO = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"

def load():
    with open(SO, "rb") as f:
        return f.read()

def dis(start, end):
    data = load()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    out = []
    for ins in md.disasm(data[start:end], start):
        out.append("%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    return out

if __name__ == "__main__":
    a, b = int(sys.argv[1], 16), int(sys.argv[2], 16)
    print("\n".join(dis(a, b)))
