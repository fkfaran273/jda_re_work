"""rngsites_probe.py - WHERE are rand/srand/time/gettimeofday called?

libsigner.so imports rand + srand + time + gettimeofday + clock_gettime
(imports_probe). Find every caller with a raw word scan: bl imm26 -> plt VA.
(plt_map keys are the branch destinations; imports dict is name->got va.)
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from elf import ELF
LIB = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
e = ELF(LIB)
t = e.byname[".text"]
off, va0, size = t["offset"], t["addr"], t["size"]
words = struct.unpack_from("<%dI" % (size // 4), e.data, off)
want = {}
for va, nm in e.plt_map.items():
    if nm.lower() in ("rand", "srand", "time", "gettimeofday", "clock_gettime",
                      "getpid", "getauxval", "syscall"):
        want[va] = nm
print("plt targets:", {hex(k): v for k, v in want.items()})
callers = {nm: [] for nm in want.values()}
for i, w in enumerate(words):
    if (w & 0xFC000000) != 0x94000000:
        continue
    imm = w & 0x3FFFFFF
    if imm & 0x2000000:
        imm -= 0x4000000
    dst = va0 + i * 4 + imm * 4
    if dst in want:
        callers[want[dst]].append(va0 + i * 4)
for nm, sites in callers.items():
    print("=== %s: %d call sites ===" % (nm, len(sites)))
    for s in sites[:16]:
        print("  0x%x" % s)

