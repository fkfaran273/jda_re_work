"""emu_walk2.py - two nSign calls in ONE emulator process: does the fold walk
change on the second signing (warm stage globals)?
usage: python emu_walk2.py
"""
import os, struct, sys, json

HERE = os.path.dirname(os.path.abspath(__file__))
REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X1, UC_ARM64_REG_SP

SITES = {0x8c48: 0x2b, 0x973a8: 0x30, 0xde08: 0x34, 0xe38c: 0x37, 0xee58: 0x38,
         0x1555c: 0x3b, 0x152b4: 0x35, 0x152e8: 0x36, 0x14df4: 0x2d,
         0xfaa0: 0x5, 0x1b550: 0x48, 0xf620: 0x7, 0x14fa8: 0x22, 0x14e7c: 0x2e}

cfg = FR.build_cfg(0)
e = E.Emu(cfg=cfg)
mu = e.mu
folds = []
state = []


def hook_state(uc, access, address, size, value, ud):
    pc = uc.reg_read(0x440)  # dummy
state_addrs = (0x155a9c, 0x155aa0, 0x155aa4, 0x155aa8)

from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from unicorn.arm64_const import UC_ARM64_REG_PC


def hw(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if address in state_addrs:
        state.append(("W", len(folds), hex(pc), hex(address),
                      hex(value & 0xFFFFFFFF)))
mu.hook_add(UC_HOOK_MEM_WRITE, hw, begin=0x155a90, end=0x155ab0)

for site, imm in SITES.items():
    def mk(s, im):
        def h(uc, address, size, ud):
            folds.append((call_no[0], hex(s), hex(uc.reg_read(UC_ARM64_REG_X1) & 0xFF)))
        return h
    mu.hook_add(UC_HOOK_CODE, mk(site, imm), begin=site, end=site)

call_no = [1]
st1 = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
blob1 = e.result.get("blob") or b""
n1 = len(folds)
print("run1: stopped=%s blob16=%s folds=%d" % (st1, blob1[:16].hex(), n1))
print("   walk:", [f[2] for f in folds])
# read the stage globals now
for a in state_addrs:
    try:
        print("   %#x = %s" % (a, bytes(mu.mem_read(a, 4)).hex()))
    except Exception as ex:
        print("   %#x err" % a)

call_no[0] = 2
try:
    st2 = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob2 = e.result.get("blob") or b""
    print("run2: stopped=%s blob16=%s folds=%d" % (st2, blob2[:16].hex(),
                                                   len(folds) - n1))
    print("   walk:", [f[2] for f in folds[n1:]])
except Exception as ex:
    print("run2 failed:", ex)
print("state writes:", state)
