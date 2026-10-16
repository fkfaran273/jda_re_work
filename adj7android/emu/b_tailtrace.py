# b_tailtrace.py — full write history of the staging tail region
# [HOME+240, HOME+320) from run start until SetByteArrayRegion(208) fires.
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552

# pass 1 to learn HOME (deterministic)
e1 = Emu()
seen = {}
orig1 = e1.jni_call
def spy1(uc, idx, x):
    if idx == 208:
        seen["src"] = x[4]
    return orig1(uc, idx, x)
e1.jni_call = spy1
out1 = e1.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
HOME = seen["src"]
print("HOME=%#x" % HOME)

e2 = Emu()
st = {"writes": [], "memcpy": [], "jni208": False, "src": None}
orig2 = e2.jni_call
def spy2(uc, idx, x):
    if idx == 208:
        st["jni208"] = True
        st["src"] = x[4]
    return orig2(uc, idx, x)
e2.jni_call = spy2

orig_plt = e2.plt_dispatch
def plt_spy(uc, name):
    if name in ("memcpy", "__memcpy_chk", "memmove", "memset"):
        a = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                      UC_ARM64_REG_X2)]
        d, s_, n = a
        near = (HOME - 0x40 <= d < HOME + 0x400) or \
               (HOME - 0x40 <= s_ < HOME + 0x400)
        if near and n and n < (1 << 16):
            st["memcpy"].append((name, d, s_, n))
    return orig_plt(uc, name)
e2.plt_dispatch = plt_spy

def hw(uc, access, address, size, value, ud):
    if st["jni208"]:
        return
    if HOME - 0x20 <= address < HOME + 0x340:
        pc = uc.reg_read(UC_ARM64_REG_PC)
        st["writes"].append((pc - BASE, address - HOME, size,
                             value & 0xFFFFFFFFFFFFFFFF))
e2.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=HEAP, end=HEAP + 0x800000)

out2 = e2.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
assert out2 == out1
print("src=%#x tail writes=%d memcpy=%d" % (st["src"] or 0,
                                            len(st["writes"]),
                                            len(st["memcpy"])))
json.dump({"HOME": HOME, "writes": st["writes"], "memcpy": st["memcpy"],
           "blob": out2.hex()},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "b_tailtrace.json"), "w"))

print("\n== writes to tail region (rel HOME), chronological ==")
for pc, off, size, val in st["writes"]:
    print("  rva %#08x  rel %+4d sz %d  %0*x" % (pc, off, size, size * 2, val))
print("\n== memcpy/memset near HOME ==")
for nm, d, s_, n in st["memcpy"]:
    print("  %s(%#x rel%+d, %#x rel%+d, %d)" %
          (nm, d, d - HOME, s_, s_ - HOME, n))
