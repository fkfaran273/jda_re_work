# Pass-2 snapshots: re-mint A and B (deterministic), snapshot heap at the
# first 4B write matching any dword of that mint's known body.
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, HEAP
from unicorn import *
from unicorn.arm64_const import *

OUT = os.path.dirname(os.path.abspath(__file__))

P1 = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
      "activity_kind": "session", "client_sdk": "android5.6.0",
      "app_version": "3.0.4"}
P2 = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
      "activity_kind": "event", "client_sdk": "android5.6.0",
      "app_version": "9.9.9", "event_token": "abcdef"}

def mint_snap2(tag, params, second):
    blob = open(os.path.join(OUT, "blob_%s.bin" % tag), "rb").read()
    body = blob[16:272]
    dw = set(struct.unpack_from("<64I", body, 0))
    e = Emu()
    snap = [None]
    def hw(uc, access, address, size, value, ud):
        if snap[0] is not None:
            return
        if size == 4 and value in dw and HEAP <= address < HEAP + 0x800000:
            snap[0] = bytes(uc.mem_read(HEAP, e.brk - HEAP))
            print(tag, "snap at write to %#x (body dword)" % address)
    e.uc.hook_add(UC_HOOK_MEM_WRITE, hw)
    out = e.run(payload=bytes(32), mapobj=params, second=second)
    assert out == blob, "non-deterministic mint?!"
    if snap[0]:
        open(os.path.join(OUT, "snap2_%s.bin" % tag), "wb").write(snap[0])
    else:
        print(tag, "no snapshot")
    return snap[0]

sA = mint_snap2("A", P1, 1791358552)
sB = mint_snap2("B", P2, 1791358553)
if sA and sB:
    print("snap sizes", len(sA), len(sB))
