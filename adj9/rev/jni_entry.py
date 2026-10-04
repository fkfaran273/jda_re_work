"""jni_entry.py - dump the TRUE entry of the nSign wrapper fn 0xda980: first 60
insns to map JNI args (x0=JNIEnv, x1=jobject/thiz, x2=Context, x3=Map,
x4=H byte[], w5=sdk?) into locals, and see where map/H/second flow.
dynsym nSign=0xdb1cc sits INSIDE 0xda980 -> 0xda980 is likely the real entry
(obfuscator split). Confirm by checking for JNI prologue patterns.
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

for entry in (0xDA980, 0xDB1CC):
    print("=== entry 0x%x (first 60) ===" % entry)
    k = pos[entry]
    for i in ins[k:k + 60]:
        print("  0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
print("done")
