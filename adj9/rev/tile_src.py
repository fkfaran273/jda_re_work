"""tile_src.py - WHICH descriptor slot does the tile repeat come from?
The #0 tile is (prefix=1, period=4): w[1..4] = [C1][C2][C3][W1] repeated 8x,
with w[0]=W0 unique. So the builder writes W0 once, then loops 8x writing the
same 4 dwords. Find the loop in sub_9afa4/sub_ba4a8 tree: a store loop with
trip count 8/9 writing 16 bytes per iter. Search 0x9afa4..0x9d000 and
0xba4a8..0xbb548 for: cbnz/cmp+b loops with small trip counts, stp q0,q1
(16B stores), or 4 consecutive str w (16B tile writes).
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

for lo, hi, nm in ((0x9AFA4, 0x9D000, "9afa4-tree"), (0xBA4A8, 0xBB548, "ba4a8")):
    print("=== %s: 16B stores + small-count loops ===" % nm)
    for i in ins:
        if not (lo <= i.address < hi):
            continue
        if i.mnemonic in ("stp",) and i.op_str.startswith("q0"):
            print("  0x%x  %s %s" % (i.address, i.mnemonic, i.op_str))
        if i.mnemonic == "mov" and ", #0x8" in i.op_str.replace(" ", "") \
                or i.op_str.strip() in ("w8, #0x8", "x8, #0x8", "w9, #8"):
            pass
    # loops: b.ne/b.eq/cbnz targeting backwards within same range
    for i in ins:
        if not (lo <= i.address < hi):
            continue
        if i.mnemonic in ("b.ne", "b.eq", "b.hi", "b.lo", "cbnz", "cbz"):
            try:
                t = int(i.op_str.split("#")[1], 16)
                if lo <= t < i.address and i.address - t < 0x200:
                    print("  loop 0x%x -> 0x%x (%s %s)"
                          % (i.address, t, i.mnemonic, i.op_str))
            except Exception:
                pass
print("done")
