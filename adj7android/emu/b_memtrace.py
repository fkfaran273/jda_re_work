# b_memtrace.py — log every PLT memcpy/memmove/memset/__memcpy_chk with
# caller LR; find the one(s) that fill the source-array tag region, and the
# digest buffer they copy from.
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu, BASE, HEAP
from unicorn import *
from unicorn.arm64_const import *

PARAMS = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
          "activity_kind": "session", "client_sdk": "android5.6.0"}
SECOND = 1791358552
COPY_PC = BASE + 0x10f834
SRC = 0x900c230            # from b_src.json (deterministic)

e = Emu()
log = {"m": [], "srcdump": None}
orig = e.plt_dispatch
def spy(uc, name):
    if name in ("memcpy", "__memcpy_chk", "memmove", "memset"):
        a = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                      UC_ARM64_REG_X2)]
        lr = uc.reg_read(UC_ARM64_REG_LR)
        d, s_, n = a
        if n and n <= 0x800:
            log["m"].append([name, d, s_ if name != "memset" else s_ & 0xFF,
                             n, lr - BASE])
    return orig(uc, name)
e.plt_dispatch = spy

def code_hook(uc, address, size, ud):
    if log["srcdump"] is None and address == COPY_PC:
        log["srcdump"] = bytes(uc.mem_read(SRC, 0x140)).hex()
e.uc.hook_add(UC_HOOK_CODE, code_hook, begin=COPY_PC, end=COPY_PC)

out = e.run(payload=bytes(32), mapobj=PARAMS, second=SECOND)
print("memcpy-ish calls: %d" % len(log["m"]))
# find calls touching SRC tag region
for name, d, s_, n, lr in log["m"]:
    tag = ""
    if d <= SRC + 272 < d + n or (d == SRC + 272):
        tag = "  <<< FILLS SRC TAG"
    if s_ == d:
        tag += " (inplace?)"
    if "SRC" in tag or (d - 0x40 <= SRC <= d + n) or SRC - 0x40 <= d <= SRC + 0x140:
        tag += " [near SRC]"
    print("  %-10s dst=%#x src=%#x n=%-4d caller rva %#x%s" %
          (name, d, s_, n, lr, tag))
json.dump(log, open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "b_memtrace.json"), "w"))
