import json, struct, sys
sys.path.insert(0, ".")
import emu_8d6f4 as E
from unicorn import *
from unicorn.arm64_const import *

WATCH = [(0x300000ffd20, 4), (0x300000ffd30, 32), (0x300000ffd50, 144)]

e = E.Emu()
events = []
md = E.md

def whook(uc, access, address, size, value, ud):
    for base, ln in WATCH:
        if base <= address < base + ln:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            events.append((e.icount, "W", address, size, value & 0xFFFFFFFF, pc))
            break

e.icount = 0
def ichook(uc, address, size, ud):
    e.icount += 1
e.mu.hook_add(UC_HOOK_CODE, ichook)

def serhook(uc, address, size, ud):
    events.append((e.icount, "SER", 0, 0, 0, address))
e.mu.hook_add(UC_HOOK_CODE, serhook, begin=0x12D39C, end=0x12D39C)

# SetByteArrayRegion hook: log when the blob is exported
_orig = e.hook_jni
# patch: wrap hook_jni to log SetByteArrayRegion icount
_base_hook = E.Emu.hook_jni
def hooked(self, uc, address, size, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    slot = pc - E.MAGIC
    nm = E.JNI_NAMES.get(slot, "")
    if nm in ("SetByteArrayRegion", "GetByteArrayRegion"):
        events.append((e.icount, nm, uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X3), 0, pc))
    return _base_hook(self, uc, address, size, ud)
E.Emu.hook_jni = hooked

e.mu.hook_add(UC_HOOK_MEM_WRITE, whook)

# also log rand draw times
_r3 = E.Emu.rand3_next
def r3(self):
    v = _r3(self)
    events.append((self.icount if hasattr(self,'icount') else 0, "RAND", v, 0, 0, 0))
    return v
# rand goes through PLT; hook instead:
rlog = []
_ehook = e.hook_plt
def ehooked(uc, address, size, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    nm = E.PLT_NAME.get(E.got_to_plt_rev.get(pc, 0), "") if False else None
    return _ehook(uc, address, size, ud)
st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
print("stopped", st)
# rand call order from e.rand_calls is ordered; get their icount by re-run? use e.calls index
print("total events:", len(events))
# summarize: first/last writes per buffer
for base, ln in WATCH:
    ws = [ev for ev in events if ev[1] == "W" and base <= ev[2] < base+ln]
    print("buf %x: %d writes, icount range %s..%s" % (base, len(ws), ws[0][0] if ws else '-', ws[-1][0] if ws else '-'))
    if ws:
        for ev in ws[:6]:
            print("   icount=%d w%d val=%08x pc=%x" % (ev[0], ev[3], ev[4], ev[5]))
        print("   ...")
        for ev in ws[-6:]:
            print("   icount=%d w%d val=%08x pc=%x" % (ev[0], ev[3], ev[4], ev[5]))
for ev in events:
    if ev[1] in ("SER", "SetByteArrayRegion", "GetByteArrayRegion"):
        print(ev[1], "icount=", ev[0], ev[2], ev[3])
