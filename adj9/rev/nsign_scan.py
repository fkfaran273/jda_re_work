"""Scan libsigner.so dynamic symbols for the JNI nSign entry and dump its head."""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nsign_scan.json")

E = ELF(SO)
hits = [s for s in E.dynsyms if "NativeLibHelper" in s["name"] or "nSign" in s["name"]]
print("nSign-like dynsyms: %d" % len(hits))
for s in hits:
    print("  %-72s va=0x%x size=0x%x" % (s["name"], s["value"], s["size"]))

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
recs = []
for s in hits:
    code = E.read(s["value"], 512)
    if not code:
        print("  unreadable: 0x%x" % s["value"])
        continue
    body = []
    for ins in md.disasm(code, s["value"]):
        extra = ""
        if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == 2:
            extra = " ; -> 0x%x" % ins.operands[0].imm
        body.append("0x%x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, extra))
        if len(body) >= 80:
            break
    recs.append({"name": s["name"], "va": s["value"], "size": s["size"], "head": body})
    print("  dumped %d insns at 0x%x" % (len(body), s["value"]))
json.dump(recs, open(OUT, "w"), indent=1)
print("saved %s" % OUT)
