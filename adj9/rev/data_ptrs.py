# data_ptrs.py - the JNI + string constants of the nSign-adjacent .text const pool:
# which code addresses in [0xDA980,0xDB1DC] load from the 0x155xxx adrp family
# (the qword grid), and does the blob pre-image live there before the VM walk?
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
import datarefs as D

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
e, refs, by_data, strs, funcs = D.build()
print("refs=%d funcs=%d" % (len(refs), len(funcs)))

# adrp resolutions whose code address falls inside the nSign frame we dumped
LO, HI = 0xDA980, 0xDB1DC
inside = sorted((c, t) for c, t in refs if LO <= c <= HI)
print("adrp inside nSign frame: %d" % len(inside))
for c, t in inside:
    mark = "  <== 0x155xxx JNI/string grid" if 0x154000 <= t < 0x157000 else ""
    print("  0x%x -> 0x%x%s" % (c, t, mark))
print("done")