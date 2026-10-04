"""dump_at.py - disassemble an exact VA range of libsigner.so.

dump_fn.py walks back to a function prologue and (as slice 117 noted) sometimes lands
on the PREVIOUS function; this dumps from the VA you give, for N instructions.
Usage: python dump_at.py 0x9afa4 3072 [grep]
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB

va = int(sys.argv[1], 16)
n = int(sys.argv[2]) if len(sys.argv) > 2 else 256
pat = sys.argv[3].lower() if len(sys.argv) > 3 else None

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
count = 0
for ins in md.disasm(elf[va:va + n * 4], va):
    line = "0x%x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str)
    if pat is None or pat in line.lower():
        print(line)
    count += 1
    if count >= n:
        break
print("# decoded %d instructions from 0x%x" % (count, va))