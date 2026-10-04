"""e2be0.py - what is sub_e2be0 (called at 0xdb21c, right BEFORE the builder)?
Args: x0=w22(saved w5=sdk?), x1=x19(saved x0=JNIEnv?). It runs BEFORE
sub_95fc4 with what looks like (sdk, env). Likely: time()/clock init, srand
seed setup, or the JNI arg unpacker. Its call tree decides what the builders
can see (second? env? map?).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
text = E.byname[".text"]
code = E.data[text["offset"]:text["offset"] + text["size"]]
ins = list(MD.disasm(code, text["addr"]))
pos = {i.address: k for k, i in enumerate(ins)}

raw = E.read(0xE2BE0, 0x1000)
sub = list(MD.disasm(raw, 0xE2BE0))
print("sub_e2be0: %d insns" % len(sub))
for i in sub[:120]:
    print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
    if i.mnemonic == "ret":
        break
print("done")
