# b_ytrace.py — writes into the blob-assembly buffer Y=0x9004e20 (fresh
# malloc holding the full blob incl. tag before its final realloc).
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552
Y = 0x9004e20

e = Emu()
ws = []
def hw(uc, access, address, size, value, ud):
    if Y <= address < Y + 0x140:
        ws.append((uc.reg_read(UC_ARM64_REG_PC) - BASE, address - Y,
                   size, value & 0xFFFFFFFFFFFFFFFF))
e.uc.hook_add(UC_HOOK_MEM_WRITE, hw, begin=Y, end=Y + 0x140)
out = e.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("writes into Y region: %d" % len(ws))
json.dump({"Y": Y, "writes": ws, "blob": out.hex()},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "b_ywrites.json"), "w"))
import collections
c = collections.Counter(pc for pc, _, _, _ in ws)
print("writer PCs:", {hex(pc): n for pc, n in c.most_common(20)})
# show writes to the tag dwords (rel 268..304)
print("\nwrites to rel 260..304:")
for pc, off, size, val in ws:
    if 260 <= off < 304:
        print("  rva %#08x rel %+d sz %d val %08x" % (pc, off, size, val & 0xFFFFFFFF))
