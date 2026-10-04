# dynsym_scan.py - list .dynsym entries of libsigner.so (the prelink .symtab being
# unreliable here), resolving VA->file offset via program headers.
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
d = E.data

sym = E.byname[".dynsym"]
strt = E.byname[".dynstr"]
n = sym["size"] // sym["entsize"]
print("dynsym entries: %d (entsize %d)" % (n, sym["entsize"]))


def v2o(va):
    for p in E.segments:
        if p["type"] == 1 and p["vaddr"] <= va < p["vaddr"] + p["filesz"]:
            return p["offset"] + (va - p["vaddr"])
    return None


named = []
for i in range(n):
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
        "<IBBHQQ", d, sym["offset"] + i * sym["entsize"])
    if st_value == 0:
        continue
    e = d.index(b"\x00", strt["offset"] + st_name)
    nm = d[strt["offset"] + st_name:e].decode(errors="replace")
    named.append((st_value, st_size, nm))
print("nonzero VAs: %d" % len(named))
for va, sz, nm in named:
    tag = ""
    if "JNI_OnLoad" in nm or "nSign" in nm or "nOnResume" in nm or "Java_" in nm:
        tag = "   <== TARGET"
    if tag or "sign" in nm.lower()[:40]:
        print("  va=0x%x size=0x%x %s%s" % (va, sz, nm[:90], tag))
print("done")