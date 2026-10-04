"""rand_op.py - identify the PRNG behind the region: disassemble the VM's RAND op
(fin_vm2.py: OP_RAND = 0x148d10) and its neighbours, and print any constants that
look like PRNG multipliers/addends, plus the imports it calls (urandom? clock?).

The 10-sample dataset (rev/als_probe.log) shows the region is 14 dwords that vary
together: #0 = [W0][T0][T1][T2][W1][T0][T1][T2]x8 (5 distinct), #2 (1), #4 (8).
If those are a PRNG stream, then region = PRNG(seed) and the seed is a function of
the second -> offline signing becomes possible once the PRNG is identified."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

for label, va in (("RAND 0x148d10", 0x148D10), ("0x148a00", 0x148A00),
                  ("0x148a10", 0x148A10), ("0x148a20", 0x148A20),
                  ("0x148980", 0x148980)):
    raw = E.read(va, 512)
    if not raw:
        print("%s: unreadable" % label)
        continue
    print("\n=== %s ===" % label)
    n = 0
    consts = []
    for ins in MD.disasm(raw, va):
        ex = ""
        if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == 2:
            t = ins.operands[0].imm
            ex = "  -> %s" % (E.plt_map.get(t) or ("sub_%x" % t))
        if ins.mnemonic in ("mov", "movk", "movz"):
            for op in ins.operands:
                if op.type == 2 and op.imm > 0xFFFF:
                    consts.append((ins.address, ins.mnemonic, ins.op_str))
        print("  0x%x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, ex))
        n += 1
        if ins.mnemonic == "ret":
            break
        if n > 90:
            print("   ... (truncated)")
            break
    if consts:
        print("   large immediates:")
        for a, m, o in consts:
            print("      0x%x %s %s" % (a, m, o))
print("\ndone")