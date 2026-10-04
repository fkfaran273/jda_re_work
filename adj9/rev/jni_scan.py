# jni_scan.py - locate the JNI registration table for the sig natives in libsigner.so
# and resolve the nSign implementation VA.
#
# The JNI names live in .dynstr (file 0xeeb / 0xf1d:
#   Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume / ..._nSign).
# Registration tables (name,sig,fn) live in .data.rel.ro with VA pointers resolved
# by the linker via R_AARCH64_RELATIVE. Scan that section for qwords pointing at
# the name strings; neighbouring .text pointers are the native bodies.
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
d = E.data

print("sections:", sorted(E.byname.keys()))
text = E.byname[".text"]
drr = E.byname[".data.rel.ro"]
dynstr = E.byname[".dynstr"]
print(".text addr=%s size=%s" % (hex(text["addr"]), hex(text["size"])))
print(".data.rel.ro addr=%s size=%s" % (hex(drr["addr"]), hex(drr["size"])))


def v2o(v):
    for sn, s in E.byname.items():
        if s["addr"] <= v < s["addr"] + s["size"] and s["size"]:
            return s["offset"] + (v - s["addr"]), sn
    return None, None


def o2v(off, sec):
    s = E.byname[sec]
    return s["addr"] + (off - s["offset"])


def cstr(off):
    e = d.index(b"\x00", off)
    return d[off:e].decode(errors="replace")


# scan .data.rel.ro for (name,sig,fn) windows; resolve string addrs via segments
names = {"nOnResume": d.find(b"Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume"),
         "nSign": d.find(b"Java_com_adjust_sdk_sig_NativeLibHelper_nSign")}


def seg_vaddr(off):
    for p in E.segments:
        if p["type"] != 1:
            continue
        if p["offset"] <= off < p["offset"] + p["filesz"]:
            return p["vaddr"] + (off - p["offset"])
    return None


strvas = {}
for name, off in names.items():
    va = seg_vaddr(off)
    print("%-9s file=%s vaddr=%s str=%r" % (name, hex(off), hex(va) if va else "?",
                                            cstr(off)[:60]))
    if va:
        strvas[name] = va

# scan .data.rel.ro for (name,sig,fn) windows
sec = drr
print("scan section:", "data.rel.ro" if "data.rel.ro" in E.byname else "data")
base, n = sec["offset"], sec["size"] // 8
qw = struct.unpack_from("<%dQ" % n, d, base)
va_of = lambda i: drr["addr"] + i * 8
strset = set(strvas.values())
hits = []
for i in range(n - 3):
    if qw[i] in strset:
        hits.append((va_of(i), [qw[i], qw[i + 1], qw[i + 2], qw[i + 3]]))
print("registration-shaped windows: %d" % len(hits))
for va, q in hits[:30]:
    tag = [nm for nm, v in strvas.items() if v == q[0]]
    fns = []
    for x in q[1:4]:
        off, sn = v2o(x)
        fns.append("%s(%s+0x%x)" % (hex(x), sn,
                                   x - E.byname[sn]["addr"]) if sn else hex(x))
    print("  tbl@%s name=%s -> %s" % (hex(va), tag[0] if tag else "?",
                                       " | ".join(fns)))
print("done")