# b_digtrace.py — all writes into the digest buffer neighborhood
# [0x900f080, 0x900f140) during the whole run; dump pre/post memory.
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552
DIG = 0x900f0c0

e = Emu()
ws = []
def hw(uc, access, address, size, value, ud):
    if DIG - 0x40 <= address < DIG + 0x60:
        ws.append((uc.reg_read(UC_ARM64_REG_PC) - BASE, address, size,
                   value & 0xFFFFFFFFFFFFFFFF))
e.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=DIG - 0x40, end=DIG + 0x60)
out = e.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("digest-neighborhood writes: %d" % len(ws))
import collections
c = collections.Counter(pc for pc, _, _, _ in ws)
print("PCs:", {hex(pc): n for pc, n in c.most_common(30)})
print("\nchronological (first 80):")
for pc, addr, size, val in ws[:80]:
    print("  rva %#08x addr %#x (rel%+d) sz %d val %0*x" %
          (pc, addr, addr - DIG, size, size * 2, val))
json.dump({"DIG": DIG, "writes": ws},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "b_digwrites.json"), "w"))
