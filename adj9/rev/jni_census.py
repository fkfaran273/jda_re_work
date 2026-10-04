import sys
sys.path.insert(0, ".")
from elf import ELF
from decryptors import LIB
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import re
e = ELF(LIB)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
t = e.byname[".text"]
off0 = e.vaddr_to_off(t["addr"])
INS = list(md.disasm(e.data[off0:off0 + t["size"]], t["addr"]))
print("DBG insns:", len(INS), flush=True)
ID = 0
for _i in INS:
    if _i.mnemonic == "blr":
        ID += 1
        if ID <= 3:
            print("DBG blr:", hex(_i.address), repr(_i.op_str), flush=True)
print("DBG total blr:", ID, flush=True)
JNI = {4: "GetVersion", 6: "FindClass", 15: "ExceptionOccurred", 17: "ExceptionClear", 21: "NewGlobalRef", 23: "DeleteLocalRef", 27: "AllocObject", 28: "NewObject", 31: "GetObjectClass", 32: "IsInstanceOf", 33: "GetMethodID", 34: "CallObjectMethod", 37: "CallBooleanMethod", 61: "CallVoidMethod", 94: "GetFieldID", 95: "GetObjectField", 100: "GetIntField", 101: "GetLongField", 111: "GetStaticMethodID", 112: "CallStaticObjectMethod", 159: "NewString", 163: "NewStringUTF", 164: "GetStringUTFLength", 165: "GetStringUTFChars", 167: "GetArrayLength", 172: "NewByteArray", 180: "GetByteArrayElements", 188: "ReleaseByteArrayElements", 196: "GetByteArrayRegion", 204: "SetByteArrayRegion", 208: "SetLongArrayRegion", 224: "ExceptionCheck"}
from collections import Counter
c = Counter()
sites = {}
for k, i in enumerate(INS):
    if i.mnemonic != "blr":
        continue
    m = re.match(r"(x\d+)", i.op_str.replace(" ", ""))
    if not m:
        continue
    dest = m.group(1)
    # walk back for ldr dest,[base,#off] with base==dest chain or env pattern
    for j in range(k - 1, max(-1, k - 8), -1):
        o = INS[j]
        if o.mnemonic != "ldr":
            continue
        mm = re.match(r"(\w+),\[(\w+),?(#(0x[0-9a-f]+|-?\d+))?\]", o.op_str.replace(" ", ""))
        if not mm:
            continue
        if mm.group(1) == dest and mm.group(3) is not None:
            _off = mm.group(3).lstrip("#")
            off = int(_off, 16) if _off.startswith("0x") else int(_off)
            c[off] += 1
            sites.setdefault(off, []).append(i.address)
            break
for off, n in sorted(c.items()):
    print(hex(off), "idx", off // 8, JNI.get(off // 8, "?"), "x", n,
          [hex(a) for a in sites[off][:4]])
