# Trace chunk-0 encryption: nonce=FF*12 mint; record all heap/stack mem ops
# until C0 (first 16B of body) lands in the home buffer; save trace.
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP
from unicorn import *
from unicorn.arm64_const import *

OUT = os.path.dirname(os.path.abspath(__file__))
params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}

e = Emu()
e.nonce12 = b"\xff" * 12
HOME = 0x9004980
trace = []
stop = [False]

def hw(uc, access, address, size, value, ud):
    if stop[0]:
        return
    trace.append(("W", address, size, value))
    if HOME <= address < HOME + 16:
        stop[0] = True
        print("C0 write at event", len(trace), "addr", hex(address))

def hr(uc, access, address, size, value, ud):
    if not stop[0]:
        trace.append(("R", address, size, 0))

e.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
e.uc.hook_add(UC_HOOK_MEM_READ, hr, begin=HEAP, end=HEAP + 0x800000)
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
print("blob body0:", out[16:32].hex())
print("trace events:", len(trace))
with open(os.path.join(OUT, "trace0.txt"), "w") as f:
    for kind, addr, size, val in trace:
        f.write("%s %x %d %x\n" % (kind, addr, size, val))
print("saved trace0.txt")
