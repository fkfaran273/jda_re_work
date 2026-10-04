# va_regions.py - print the VA->file-offset table for libsigner.so regions the VM
# cares about: JNI bodies, the rodata blob range (0x155xxx adrp family), the
# .init_array / .fini_array / .data.rel.ro windows, and the string table phrases.
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
d = E.data

print("file VA windows (PIE base + file offset):")
for sn in (".text", ".rodata", ".data.rel.ro", ".data", ".init_array",
           ".fini_array", ".dynstr", ".dynamic", ".got", ".bss"):
    s = E.byname.get(sn)
    if not s:
        continue
    print("  %-14s va=%s off=%s size=%s" % (sn, hex(s["addr"]), hex(s["offset"]),
                                            hex(s["size"])))

# the two JNI names in .dynstr -> their VAs + who else sits between them
strt = E.byname[".dynstr"]
i1 = d.find(b"Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume")
i2 = d.find(b"Java_com_adjust_sdk_sig_NativeLibHelper_nSign")
o2v = lambda o: E.vaddr_to_off(E.byname[".dynstr"]["addr"]) or None
for nm, off in (("nOnResume", i1), ("nSign", i2)):
    seg = None
    for p in E.segments:
        if p["type"] == 1 and p["offset"] <= off < p["offset"] + p["filesz"]:
            seg = p
    va = seg["vaddr"] + (off - seg["offset"]) if seg else None
    print("%-9s file=0x%x va=%s" % (nm, off, hex(va) if va else "?"))

# .dynsym entries whose value lands in .text (already found 2) + their sizes
sym = E.byname[".dynsym"]
strb = E.byname[".dynstr"]
n = sym["size"] // sym["entsize"]
print("dynsym .text entries:")
for i in range(n):
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
        "<IBBHQQ", d, sym["offset"] + i * sym["entsize"])
    if not st_value:
        continue
    e = d.index(b"\x00", strb["offset"] + st_name)
    nm = d[strb["offset"] + st_name:e].decode(errors="replace")
    print("  va=0x%x size=0x%x %s" % (st_value, st_size, nm[:80]))
print("done")