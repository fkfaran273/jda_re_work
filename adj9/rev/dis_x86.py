#!/usr/bin/env python3
"""Disassemble a VA range from the x86_64 libsigner.so."""
import sys, struct
from capstone import *

FN = "../../extracted/_ref/sigs/sig500_x86_64.so"
d = open(FN, "rb").read()

# build vaddr -> offset map
e_phoff, = struct.unpack_from("<Q", d, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", d, o)
    if p_type == 1:
        segs.append((p_vaddr, p_off, p_filesz))

def v2o(va):
    for v, o, sz in segs:
        if v <= va < v + sz:
            return o + (va - v)
    return None

start = int(sys.argv[1], 16)
n = int(sys.argv[2]) if len(sys.argv) > 2 else 300
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
s = v2o(start)
print("; file offset 0x%x  n=%d" % (s, n))
code = d[s:s + n * 8]
for ins in md.disasm(code, start):
    print("0x%x  %-30s %s" % (ins.address, ins.mnemonic, ins.op_str))
    if len(sys.argv) > 3 and ins.mnemonic == "ret":
        break
