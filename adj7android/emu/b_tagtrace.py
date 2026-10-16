# b_tagtrace.py — locate the digest buffer + hashing-core PCs.
# Pass 1: find staging home via SetByteArrayRegion(208) src.
# Pass 2: log every heap write armed from the moment body[255] (HOME+271)
#         is stored until the tag copy into HOME+272..304 is done.
import sys, os, json, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552

# ---------------- pass 1: find staging src
e1 = Emu()
seen = {}
orig1 = e1.jni_call
def spy1(uc, idx, x):
    if idx == 208:
        seen["src"] = x[4]
        seen["len"] = x[3]
    return orig1(uc, idx, x)
e1.jni_call = spy1
out1 = e1.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
HOME = seen["src"]
print("pass1 staging HOME=%#x len=%s blob_ok=%s" % (HOME, seen.get("len"),
                                                    out1 is not None))

# ---------------- pass 2: armed write trace
e2 = Emu()
st = {"armed": False, "done": False, "writes": [], "memcpy": [], "src": None}
orig2 = e2.jni_call
def spy2(uc, idx, x):
    if idx == 208:
        st["src"] = x[4]
    return orig2(uc, idx, x)
e2.jni_call = spy2

orig_plt = e2.plt_dispatch
def plt_spy(uc, name):
    if name in ("memcpy", "__memcpy_chk", "memmove") and st["armed"]:
        a = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                      UC_ARM64_REG_X2)]
        st["memcpy"].append((a[0], a[1], a[2]))
    return orig_plt(uc, name)
e2.plt_dispatch = plt_spy

def hw(uc, access, address, size, value, ud):
    if st["done"] or not (HEAP <= address < HEAP + 0x800000):
        return
    if not st["armed"]:
        # arm when a write covers HOME+271 (last body byte)
        if address <= HOME + 271 < address + size:
            st["armed"] = True
        else:
            return
    pc = uc.reg_read(UC_ARM64_REG_PC)
    st["writes"].append((pc, address, size, value & ((1 << (size * 8)) - 1)
                         if size <= 8 else 0))
    # done when all 32 tag bytes covered
    if address <= HOME + 303 < address + size:
        st["done"] = True
e2.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=HEAP, end=HEAP + 0x800000)

out2 = e2.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("pass2 src=%#x armed=%s writes=%d memcpy=%d" %
      (st["src"] or 0, st["armed"], len(st["writes"]), len(st["memcpy"])))
assert out2 == out1, "nondeterministic!"

json.dump({"HOME": HOME, "writes": st["writes"], "memcpy": st["memcpy"],
           "blob": out2.hex()}, open(os.path.join(os.path.dirname(
               os.path.abspath(__file__)), "b_tagtrace.json"), "w"))

# ---------------- analysis: which PCs write where (rva space)
pc_count = collections.Counter()
pc_regions = collections.defaultdict(set)
for pc, addr, size, val in st["writes"]:
    pc_count[pc - BASE] += 1
    pc_regions[pc - BASE].add((addr - HOME))
print("\nwriter PCs (rva) -> offsets rel. HOME:")
for pc, n in pc_count.most_common(30):
    offs = sorted(pc_regions[pc])
    rng = "%+d..%+d" % (offs[0], offs[-1]) if offs else ""
    print("  rva %#x  n=%-4d offs %s" % (pc, n, rng))
print("\nmemcpy calls in window:")
for d, s, n in st["memcpy"]:
    tag = ""
    if HOME <= d < HOME + 0x400: tag += " DSTrel%+d" % (d - HOME)
    if HOME <= s < HOME + 0x400: tag += " SRCrel%+d" % (s - HOME)
    print("  memcpy(%#x, %#x, %d)%s" % (d, s, n, tag))
print("\nlast 12 writes:")
for pc, addr, size, val in st["writes"][-12:]:
    print("  rva %#x -> %#x (rel %+d) sz %d val %x" %
          (pc - BASE, addr, addr - HOME, size, val))
