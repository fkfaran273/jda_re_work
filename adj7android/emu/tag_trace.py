# Trace the tag computation: locate the blob staging buffer (via
# SetByteArrayRegion src), then hook writes into its tag region to get PCs.
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP, STACK
from unicorn import *
from unicorn.arm64_const import *

params = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}

e = Emu()
stage = {}

orig_jni = e.jni_call
def jni_spy(uc, idx, x):
    if idx == 208:                       # SetByteArrayRegion
        stage["src"] = x[4]
        stage["len"] = x[2] if not isinstance(x[2], int) or x[2] < 4096 else 0
    return orig_jni(uc, idx, x)
e.jni_call = jni_spy
out = e.run(payload=bytes(32), mapobj=params, second=1791358552)
print("blob:", out.hex()[:32], "...")
src = stage.get("src", 0)
print("staging src buffer: %#x  homes: %s" % (src, stage.get("homes")))

# second pass: hook writes to [src+272, src+304)
writes = []
e2 = Emu()
stage2 = {}
orig2 = e2.jni_call
def jni_spy2(uc, idx, x):
    if idx == 208:
        stage2["src"] = x[4]
    return orig2(uc, idx, x)
e2.jni_call = jni_spy2
armed = [False]
def hook_w(uc, access, address, size, value, ud):
    if HOME and HOME + 240 <= address < HOME + 304:
        writes.append((uc.reg_read(UC_ARM64_REG_PC), address, size, value))
e2.uc.hook_add(UC_HOOK_MEM_WRITE, hook_w)
# arm only once staging is known from pass 1 (same allocation pattern)
armed[0] = True
import sign_emu
HOME = stage.get("src")
print("watching HOME", hex(HOME))
out2 = e2.run(payload=bytes(32), mapobj=params, second=1791358552)
print("pass2 src:", hex(stage2.get("src", 0)), "writes:", len(writes))
seen = {}
for pc, addr, size, value in writes:
    seen.setdefault(pc, 0)
    seen[pc] += 1
print("writer PCs into tag region:")
for pc, n in sorted(seen.items()):
    print("  pc=%#x (rva %#x)  %d writes" % (pc, pc - BASE if pc > BASE else 0, n))
