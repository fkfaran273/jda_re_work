"""builder_args.py - what feeds the descriptor builders? Dump the nSign wrapper
around the sub_95fc4 call at 0xdb24c (args in x0-x5) and the sub_bb548 call at
0xdbb64. The wrapper fn is 0xda980 (giant state machine, hub at 0xdaad0).
Straight-line context +/-30 insns around each call site names the inputs:
(ctx/map/H/second?) -> builders. This decides whether builders CAN see the
second, the map, H, or only opaque handles.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
text = E.byname[".text"]
code = E.data[text["offset"]:text["offset"] + text["size"]]
ins = list(MD.disasm(code, text["addr"]))
pos = {i.address: k for k, i in enumerate(ins)}

for site, nm in ((0xDB24C, "sub_95fc4(builder)"), (0xDBB64, "sub_bb548(asm)")):
    k = pos[site]
    print("=== around 0x%x (%s) ===" % (site, nm))
    for i in ins[max(0, k - 30):k + 10]:
        print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
