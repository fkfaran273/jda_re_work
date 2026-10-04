"""Does the post-head d0 depend on the CLAIMS, or only on the SEED?

Run nSign with a FIXED seed (urandom8) under two different claim sets and
compare the head sequence (w1 values at the tail wrapper 0x1441e4) and the
final post-head d0. If identical -> post-head d0 is a pure function of the
seed, and we can compute it offline per-seed and feed the Python body builder.
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(os.path.join(HERE, "..", ".."))
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

TAIL = 0x1441e4
SIGNER_RET = 0xdb1c4

SEED = 0x5a9b1400

def run_with(strvals, seed=SEED, sec=1789240512):
    cfg = dict(E.DEF_CFG)
    ur = (seed & 0xFFFFFFFF).to_bytes(4, "little") + b"\x11\x22\x33\x44"
    cfg["urandom8"] = ur
    cfg["sec"] = sec
    cfg["strvals"] = strvals
    e = E.Emu(cfg)
    mu = e.mu
    head = []
    ctx_ref = {}
    def h_tail(uc, addr, size, ud):
        head.append(uc.reg_read(UC_ARM64_REG_W1))
        ctx_ref.setdefault("ctx", uc.reg_read(UC_ARM64_REG_X0))
    def h_ret(uc, addr, size, ud):
        c = ctx_ref.get("ctx")
        if c is not None:
            ctx_ref["d0"] = [struct.unpack_from("<H", bytes(uc.mem_read(c + 0x30 + 2*i, 2)))[0]
                              for i in range(72)]
    mu.hook_add(UC_HOOK_CODE, h_tail, begin=TAIL, end=TAIL)
    mu.hook_add(UC_HOOK_CODE, h_ret, begin=SIGNER_RET, end=SIGNER_RET)
    st = e.run(0xDB1CC, count=400_000_000, argstyle="nsign")
    return st, head, ctx_ref.get("d0"), e

base = {"secret_id": "s3cr3t", "client_sdk": "android5.7.0",
        "environment": "production", "app_version": "3.13.9",
        "android_id": None, "fire_adid": None, "default": "emu-string"}
# Variant A: minimal
A = dict(base)
# Variant B: add a bunch of claim keys / change values -> stresses claim-dependence
B = dict(base)
B.update({"gps_adid": "cc87d5c7-46cf-47db-8209-b138c922aca7",
          "app_token": "jut9tib0eeps", "device_name": "moto g42",
          "device_manufacturer": "motorola", "os_version": "12",
          "api_level": "31", "package_name": "com.penti.app",
          "language": "en", "source": "install_referrer"})

stA, headA, d0A, eA = run_with(A)
stB, headB, d0B, eB = run_with(B)
print("A: stopped=%s headcalls=%d" % (stA, len(headA)))
print("   head seq:", [hex(x) for x in headA])
print("B: stopped=%s headcalls=%d" % (stB, len(headB)))
print("   head seq:", [hex(x) for x in headB])
print("HEAD SEQ IDENTICAL (same seed, diff claims):", headA == headB)
if d0A and d0B:
    print("POST-HEAD d0 IDENTICAL:", d0A == d0B)
else:
    print("d0 capture missing", d0A is None, d0B is None)
# also confirm blob emitted
print("A blob len:", len(eA.result.get("blob") or b""))
print("A result stopped:", eA.result.get("stopped"))
