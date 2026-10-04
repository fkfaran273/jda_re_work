"""plt_lookup.py - resolve PLT stubs to import names, and list every import of
libsigner.so. RAND (0x148d10) is a PLT stub, so this names the actual entropy
source the VM uses for the per-call region."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
print("imports (%d):" % len(E.plt_map))
for va in sorted(E.plt_map):
    print("  0x%-7x %s" % (va, E.plt_map[va]))
print("\n=== named stubs ===")
for va in (0x148A00, 0x148A10, 0x148A20, 0x148D10, 0x14868, 0x1483E0):
    print("  0x%x -> %s" % (va, E.plt_map.get(va, "?")))
print("\n=== RAND-relevant imports present? ===")
want = ("rand", "random", "urandom", "getrandom", "arc4random", "clock",
        "time", "gettimeofday", "pthread", "malloc", "calloc", "free", "memcpy",
        "memset", "hmac", "sha", "md5", "aes", "syscall", "open", "read")
for k in sorted(E.imports):
    if any(w in k.lower() for w in want):
        print("  %-28s 0x%x" % (k, E.imports[k]))
print("done")