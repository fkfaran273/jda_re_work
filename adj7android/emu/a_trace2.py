# FF-nonce mint: write-trace always; read-trace (with values) armed only in
# the write-count window [22,335,000, 22,378,000] which brackets chunk-0's
# encryption (C0 dword first written at W#22,362,375 in trace1).
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

ARM_AT, STOP_AT = 22_335_000, 22_378_000
W = []
R = []
wc = [0]
armed = [False]
KEYLO, KEYHI = HEAP + 0xe3e8, HEAP + 0xe6e8   # key block bpd region


def hw(uc, access, address, size, value, ud):
    wc[0] += 1
    if armed[0]:
        if wc[0] > STOP_AT:
            return
    elif wc[0] >= ARM_AT:
        armed[0] = True
        print("ARM at W#", wc[0])
    if armed[0] and wc[0] <= STOP_AT:
        W.append((uc.reg_read(UC_ARM64_REG_PC), address, size, value))


def hr(uc, access, address, size, value, ud):
    if not armed[0] or wc[0] > STOP_AT:
        return
    try:
        v = int.from_bytes(bytes(uc.mem_read(address, size)), "little")
    except Exception:
        v = 0
    R.append((uc.reg_read(UC_ARM64_REG_PC), address, size, v))


e.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
e.uc.hook_add(UC_HOOK_MEM_READ, hr, begin=HEAP, end=HEAP + 0x800000)
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
print("blob ok:", out is not None and out[16:32].hex().startswith("4da745a0"))
print("W in window:", len(W), "R in window:", len(R))
with gzip.open(os.path.join(OUT, "trace2.txt.gz"), "wt") as f:
    for pc, a, s, v in R:
        f.write("R %x %x %d %x\n" % (pc, a, s, v))
    f.write("=== WRITES ===\n")
    for pc, a, s, v in W:
        f.write("W %x %x %d %x\n" % (pc, a, s, v))
print("saved trace2.txt.gz")
