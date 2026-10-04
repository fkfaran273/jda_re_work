# text_meta.py - header + relocation summaries of libsigner.so, offline.
# Answers: toolchain markers, JNI register style, and which .text spans the
# VM-walk family could cover (the FinEx emulator + WH4 ground truth).
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
d = E.data
print("ehdr: e_machine=%s e_entry=0x%x" % (d[0x12], struct.unpack_from("<Q", d, 0x18)[0]))
print("comment:", E.byname[".comment"]["size"], "bytes")
c = E.byname[".comment"]
print("  ", d[c["offset"]:c["offset"] + c["size"]][:160])
bid = E.byname[".note.gnu.build-id"]
print("build-id:", d[bid["offset"]:bid["offset"] + bid["size"]].hex())
ai = E.byname[".note.android.ident"]
ab = d[ai["offset"]:ai["offset"] + ai["size"]]
print("android.ident:", ab.hex())

# rodata ascii harvest (short tokens the VM references as kinds)
r = E.byname[".rodata"]
blob = d[r["offset"]:r["offset"] + r["size"]]
print(".rodata size=0x%x at va=0x%x" % (r["size"], r["addr"]))
toks = sorted({m.group(0).decode() for m in __import__("re").finditer(rb"[ -~]{5,}", blob)})
print("rodata tokens: %d" % len(toks))
for t in toks:
    print("  ", t)

# import table: PLT/GOT shape -> which libc entry points the VM calls
for sn in (".got", ".got.plt", ".plt"):
    s = E.byname.get(sn)
    if s:
        print("%-9s va=0x%x size=0x%x" % (sn, s["addr"], s["size"]))
print("done")