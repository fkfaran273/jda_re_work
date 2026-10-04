"""Run native nSign once; dump its output blob, post-head d0, and compare the
native body against the Python body builder (fed the SAME post-head d0).
Goal: confirm the Python FinEx/body path is byte-exact with the native, and
understand the exact native signature format so we can ship it directly.
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
SEC = 1789240512

strvals = {"secret_id": "s3cr3t", "client_sdk": "android5.7.0",
           "environment": "production", "app_version": "3.13.9",
           "android_id": None, "fire_adid": None, "default": "emu-string"}

cfg = dict(E.DEF_CFG)
cfg["urandom8"] = (SEED & 0xFFFFFFFF).to_bytes(4, "little") + b"\x11\x22\x33\x44"
cfg["sec"] = SEC
cfg["strvals"] = strvals
e = E.Emu(cfg)
mu = e.mu
state = {"head": [], "ctx": None, "d0": None}

def h_tail(uc, addr, size, ud):
    state["head"].append(uc.reg_read(UC_ARM64_REG_W1))
    state.setdefault("ctx", uc.reg_read(UC_ARM64_REG_X0))
def h_ret(uc, addr, size, ud):
    c = state.get("ctx")
    if c is not None:
        state["d0"] = [struct.unpack_from("<H", bytes(uc.mem_read(c + 0x30 + 2*i, 2)))[0]
                       for i in range(72)]
mu.hook_add(UC_HOOK_CODE, h_tail, begin=TAIL, end=TAIL)
mu.hook_add(UC_HOOK_CODE, h_ret, begin=SIGNER_RET, end=SIGNER_RET)

st = e.run(0xDB1CC, count=400_000_000, argstyle="nsign")
blob = e.result.get("blob") or b""
print("stopped:", st)
print("head seq:", [hex(x) for x in state["head"]])
print("post-head d0 (72 hw):", " ".join("%04x" % v for v in (state["d0"] or [])))
print("blob len:", len(blob))
print("blob hex:", blob.hex())

# does make_header(SEC) appear in the blob?
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "..", "adj9_tool"))
import adj9_signer as S
hdr = S.make_header(SEC) if hasattr(S, "make_header") else None
print("make_header(SEC):", hdr.hex() if hdr else "n/a")
if hdr:
    print("header found in blob at:", blob.find(hdr))
