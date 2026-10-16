# b_valtrace.py — global write-value trace: find the FIRST store anywhere
# (heap/stack/lib) carrying the nSign tag dword 0x2dbf6161 (and the other
# tag dwords). That is the hash core's output store.
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552
TAG_DWORDS = [0x2dbf6161, 0xdc5dc5b0, 0xaa8a90ec, 0x1309fe4a,
              0xab3f36f9, 0x41d711c0, 0x5c60726b, 0xffebbf00]
FIRST = TAG_DWORDS[0]

e = Emu()
hits = []
stop_at = [None]
def hw(uc, access, address, size, value, ud):
    if size == 4:
        if (value & 0xFFFFFFFF) == FIRST:
            hits.append((uc.reg_read(UC_ARM64_REG_PC) - BASE, address,
                         size, value & 0xFFFFFFFF))
    elif size == 8:
        v = value & 0xFFFFFFFFFFFFFFFF
        lo, hi = v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF
        if FIRST in (lo, hi):
            hits.append((uc.reg_read(UC_ARM64_REG_PC) - BASE, address,
                         size, v))
e.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
out = e.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("stores of tag dword0 0x%08x: %d" % (FIRST, len(hits)))
for pc, addr, size, val in hits:
    print("  rva %#08x  addr %#x sz %d val %016x" % (pc, addr, size, val))
json.dump(hits, open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "b_valtrace.json"), "w"))
