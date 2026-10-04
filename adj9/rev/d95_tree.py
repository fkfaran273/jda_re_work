"""d95_tree.py - the descriptor builders: sub_95fc4 is called ONCE from the nSign
wrapper (0xdb24c), but it is a 186-insn DISPATCH HUB (fn_95fc4.log: no direct
rand/time calls, only pthread_detach/create + sub_9afa4 + atomic). The REAL
per-desc builders hang off it. Expand: which functions does the 0xba4a8 tree
(sub_9afa4 x4 + malloc + atomics) vs the 0x956e4 tree (10 frees?!) build?
And where do #0 (144B), #4 (32B), #2 (4B) buffers get FILLED (memset? memcpy
from a keyed transform? HMAC?).

Dump: fn_956e4.log call list (already have), fn_ba4a8 body for buffer-fill
patterns (str/ldp chains with small offsets = struct fill).
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

# buffer-fill pattern: consecutive str wX,[xY,#off] with small offs inside
# 0xba4a8..0xbb548 (the TRUE builder entry 0xba4a8, 1064 insns)
n = 0
for i in ins:
    if 0xBA4A8 <= i.address < 0xBB548 and i.mnemonic in ("str", "stp", "strb"):
        print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
        n += 1
        if n > 80:
            break
print("stores shown: %d" % n)
print("done")
