# b_srctrace.py — dump the copy-out source array at rva 0x10f834, then
# (pass 2) trace writes into the source array's tag region to find the
# real tag writers.
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552
COPY_PC = BASE + 0x10f834

# ---------------- pass 1: capture source ptr at copy-out
e1 = Emu()
info = {"hits": 0}
def code_hook(uc, address, size, ud):
    if address != COPY_PC:
        return
    info["hits"] += 1
    if info["hits"] == 1:
        x22 = uc.reg_read(UC_ARM64_REG_X22)
        src = struct.unpack_from("<Q", bytes(uc.mem_read(x22 + 8, 8)))[0]
        info["x22"] = x22
        info["src"] = src
        info["dst"] = uc.reg_read(UC_ARM64_REG_X13)
        info["idx"] = uc.reg_read(UC_ARM64_REG_X5)
        info["lenfld"] = struct.unpack_from("<Q", bytes(
            uc.mem_read(x22 + 0x10, 8)))[0]
        info["srcdump"] = bytes(uc.mem_read(src, 0x140)).hex()
        info["x22dump"] = bytes(uc.mem_read(x22 - 0x20, 0x60)).hex()
e1.uc.hook_add(UC_HOOK_CODE, code_hook, begin=COPY_PC, end=COPY_PC)
out1 = e1.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("copy hits=%d x22=%#x src=%#x dst=%#x idx=%d lenfld=%s" %
      (info["hits"], info.get("x22", 0), info.get("src", 0),
       info.get("dst", 0), info.get("idx", -1), info.get("lenfld")))
sd = bytes.fromhex(info["srcdump"])
# source holds blob as BE dwords: natural bytes = rev each dword
nat = b"".join(sd[i:i + 4][::-1] for i in range(0, len(sd), 4))
print("src natural[0:16]:", nat[:16].hex().upper())
print("blob      [0:16]:", out1[:16].hex().upper())
print("src natural[272:304]:", nat[272:304].hex().upper())
print("blob      [272:304]:", out1[272:304].hex().upper())
json.dump(info, open(os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "b_src.json"), "w"))

# ---------------- pass 2: writes into src array tail (tag region)
SRC = info["src"]
e2 = Emu()
w2 = []
def hw(uc, access, address, size, value, ud):
    if SRC - 0x20 <= address < SRC + 0x140:
        w2.append((uc.reg_read(UC_ARM64_REG_PC) - BASE, address - SRC,
                   size, value & 0xFFFFFFFFFFFFFFFF))
e2.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=HEAP, end=HEAP + 0x800000)
out2 = e2.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
assert out2 == out1
print("\nwrites into src region: %d" % len(w2))
for pc, off, size, val in w2:
    print("  rva %#08x  rel %+4d sz %d  %0*x" % (pc, off, size, size * 2, val))
json.dump({"SRC": SRC, "writes": w2},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "b_srcwrites.json"), "w"))
