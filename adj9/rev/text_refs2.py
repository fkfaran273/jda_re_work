# text_refs2.py - direct (offset,value) table of every qword in .data.rel.ro that
# resolves inside libsigner.so, with the string decoded when it lands in .dynstr
# or .rodata. Then the same for the first 256 qwords of .data (the EMIT-grid).
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
d = E.data


def seg_of(off):
    for p in E.segments:
        if p["type"] == 1 and p["offset"] <= off < p["offset"] + p["filesz"]:
            return p
    return None


def va(off):
    p = seg_of(off)
    return p["vaddr"] + (off - p["offset"]) if p else None


def asc(off):
    try:
        e = d.index(b"\x00", off)
        t = d[off:e]
        if 6 <= len(t) <= 64 and all(32 <= b < 127 for b in t):
            return t.decode()
    except Exception:
        pass
    return None


for sn in (".data.rel.ro", ".data"):
    s = E.byname[sn]
    n = s["size"] // 8
    print("== %s qwords=%d ==" % (sn, n))
    for i in range(n):
        q = struct.unpack_from("<Q", d, s["offset"] + i * 8)[0]
        if q < 0x1000:
            continue
        mark = ""
        for sec2 in (".text", ".rodata", ".dynstr", ".data.rel.ro", ".data",
                     ".bss", ".got", ".plt"):
            s2 = E.byname.get(sec2)
            if s2 and s2["addr"] <= q < s2["addr"] + s2["size"]:
                mark = sec2
                break
        if not mark:
            continue
        extra = ""
        for sec2 in (".dynstr", ".rodata"):
            s2 = E.byname.get(sec2)
            if s2 and s2["addr"] <= q < s2["addr"] + s2["size"]:
                off = s2["offset"] + (q - s2["addr"])
                t = asc(off)
                if t:
                    extra = " %r" % t
        print("  +0x%-5x = %-18s in %-12s%s" % (i * 8, hex(q), mark, extra))
print("done")