# rodata_addrs.py - which .text ADRP family each .rodata/-relro address belongs to,
# and the JNI + string constants each family references. Uses datarefs' page map.
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
import datarefs as D

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
d = E.data
e, refs, by_data, strs, funcs = D.build()

print("=== rodata / .data.rel.ro qwords that look like code or string pointers ===")
for sn in (".rodata", ".data.rel.ro", ".data"):
    s = E.byname.get(sn)
    if not s:
        continue
    blob = d[s["offset"]:s["offset"] + s["size"]]
    n = len(blob) // 8
    print("-- %s va=0x%x size=0x%x qwords=%d" % (sn, s["addr"], s["size"], n))
    for i in range(n):
        q = struct.unpack_from("<Q", blob, i * 8)[0]
        va = s["addr"] + i * 8
        hits = by_data.get(va, [])
        # classify the pointer itself
        cls = None
        if 0x8BE0 <= q < 0x8BE0 + 0x13FDD4:
            cls = "text+0x%x" % (q - 0x8BE0)
        for sec, pat in ((".dynstr", rb"[\x20-\x7e]{6,}"),
                         (".rodata", rb"[\x20-\x7e]{6,}")):
            s2 = E.byname.get(sec)
            if s2 and s2["addr"] <= q < s2["addr"] + s2["size"]:
                try:
                    e2 = d.index(b"\x00", s2["offset"] + (q - s2["addr"]))
                    tok = d[s2["offset"] + (q - s2["addr"]):e2][:48]
                    if re.fullmatch(rb"[ -~]{6,}", tok):
                        cls = "str %r" % tok.decode()
                except Exception:
                    pass
        if cls or hits:
            print("  0x%x = %-46s refs=%d %s" % (va, cls or hex(q), len(hits),
                                                 [hex(c) for c in hits[:4]]))
print("done")