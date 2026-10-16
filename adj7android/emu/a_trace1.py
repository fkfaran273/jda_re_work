# Full FF-nonce mint: write-trace always; read-trace armed between record-build
# start and C0 landing. Goal: capture the chunk-0 SPN encryption dataflow.
import sys, os, struct, gzip
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

OUT = os.path.dirname(os.path.abspath(__file__))
params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552

e = Emu()
e.nonce12 = b"\xff" * 12

C0 = bytes.fromhex("4da745a0be7da89170af6e32246cd7d6")
c0d = set()
for i in (0, 4, 8, 12):
    c0d.add(struct.unpack("<I", C0[i:i+4])[0])       # plain-domain dword
    c0d.add(struct.unpack("<I", C0[i:i+4][::-1])[0])  # swap4-domain dword

W = []          # (pc, addr, size, val)  always
R = []          # (pc, addr, size, val)  armed window only
arm = [False]
done = [False]

def hw(uc, access, address, size, value, ud):
    if done[0]:
        return
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if not arm[0]:
        b = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
        if b'{ "a' in b or b'1844' in b:
            arm[0] = True
            print("ARM at W count", len(W), "pc %#x" % pc)
    W.append((pc, address, size, value))
    if arm[0] and size == 4 and (value & 0xFFFFFFFF) in c0d:
        done[0] = True
        print("C0 dword write! W count", len(W), "R count", len(R), "pc %#x" % pc)

def hr(uc, access, address, size, value, ud):
    if not arm[0] or done[0]:
        return
    try:
        v = int.from_bytes(bytes(uc.mem_read(address, size)), "little")
    except Exception:
        v = 0
    R.append((uc.reg_read(UC_ARM64_REG_PC), address, size, v))

e.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
e.uc.hook_add(UC_HOOK_MEM_READ, hr, begin=HEAP, end=HEAP + 0x800000)
out = e.run(payload=bytes(32), mapobj=params, second=SECOND)
print("blob:", out.hex() if out else None)
print("W events:", len(W), "R events:", len(R))
with gzip.open(os.path.join(OUT, "trace1.txt.gz"), "wt") as f:
    for pc, a, s, v in W:
        f.write("W %x %x %d %x\n" % (pc, a, s, v))
    f.write("=== READS ===\n")
    for pc, a, s, v in R:
        f.write("R %x %x %d %x\n" % (pc, a, s, v))
heap = bytes(e.uc.mem_read(HEAP, 0x11540))
open(os.path.join(OUT, "heap_ff.bin"), "wb").write(heap)
print("saved trace1.txt.gz heap_ff.bin")
