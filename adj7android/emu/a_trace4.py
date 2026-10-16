# FF-nonce mint: interleave R+W with values, armed at the FIRST read of the
# key block (0x900e3e8..0x900e6e8), stopped ~1.2 key passes later.
import sys, os, gzip
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP
from unicorn import *
from unicorn.arm64_const import *

OUT = os.path.dirname(os.path.abspath(__file__))
params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}

e = Emu()
e.nonce12 = b"\xff" * 12

KEYLO, KEYHI = HEAP + 0xe3e8, HEAP + 0xe6e8
EV = []
armed = [False]
kbcnt = [0]
STOP_AFTER_KEYHITS = 400

def keyhook(uc, access, address, size, value, ud):
    kbcnt[0] += 1
    if not armed[0]:
        armed[0] = True
        print("ARM: first key read at W? addr=%#x" % address)

def hw(uc, access, address, size, value, ud):
    if not armed[0]:
        return
    if kbcnt[0] >= STOP_AFTER_KEYHITS:
        return
    EV.append((1, uc.reg_read(UC_ARM64_REG_PC), address, size, value))

def hr(uc, access, address, size, value, ud):
    if not armed[0] or kbcnt[0] >= STOP_AFTER_KEYHITS:
        return
    try:
        v = int.from_bytes(bytes(uc.mem_read(address, size)), "little")
    except Exception:
        v = 0
    EV.append((0, uc.reg_read(UC_ARM64_REG_PC), address, size, v))

e.uc.hook_add(UC_HOOK_MEM_READ, keyhook, begin=KEYLO, end=KEYHI)
e.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
e.uc.hook_add(UC_HOOK_MEM_READ, hr, begin=HEAP, end=HEAP + 0x800000)
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
print("blob ok:", out is not None and out[16:32].hex().startswith("4da745a0"))
print("events:", len(EV), "keyhits:", kbcnt[0])
with gzip.open(os.path.join(OUT, "trace4.txt.gz"), "wt") as f:
    for w, pc, a, s, v in EV:
        f.write("%s %x %x %d %x\n" % ("W" if w else "R", pc, a, s, v))
print("saved trace4.txt.gz")
