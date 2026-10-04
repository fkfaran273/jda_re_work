"""Trace every write into the signer ctx (0x300000ffd20) with its PC, to
determine which code writes the EMITTED d0 (ctx+0x30) vs the working buffer
(ctx+0x18), and when."""
import os, sys, json, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(os.path.join(HERE, "..", ".."))
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.arm64_const import *

TAIL = 0x1441e4; PM = 0x1437c8; SIGNER_RET = 0xdb1c4
PHASE1 = 0x1437ec; WHIT = 0x144074

e = E.Emu(); mu = e.mu
head = []; info = {}; writes = []

CTX = None
LO = 0x300000ffd20; HI = 0x300000ffe10

def hw(buf, base, n): return [struct.unpack_from("<H", buf, base + 2 * i)[0] for i in range(n)]
def snap(addr, n=72): return hw(bytes(mu.mem_read(addr, 0x30 + 2 * n)), 0x30, n)

def h_tail(uc, addr, size, ud):
    w1 = uc.reg_read(UC_ARM64_REG_W1); x0 = uc.reg_read(UC_ARM64_REG_X0)
    head.append({"w1": w1, "ctx": x0}); info.setdefault("ctx", x0)

def h_pm(uc, addr, size, ud):
    ctx = uc.reg_read(UC_ARM64_REG_X19)
    info["ctx_pm"] = ctx; info["phase1_d0"] = snap(ctx, 72)

def h_seed(uc, addr, size, ud):
    info["seed"] = uc.reg_read(UC_ARM64_REG_W1)

def h_ret(uc, addr, size, ud):
    ctx = info.get("ctx")
    if ctx is not None:
        info["posthead_d0"] = snap(ctx, 72)
        info["working_18"] = hw(bytes(uc.mem_read(ctx, 0x1a0)), 0x18, 0x90)
    # mark end
    writes.append({"ev": "SIGNER_RET"})

def h_memw(uc, access, addr, size, value, ud):
    if LO <= addr < HI:
        writes.append({"ev": "W", "pc": uc.reg_read(UC_ARM64_REG_PC),
                       "off": addr - LO, "sz": size, "val": value,
                       "nhead": len(head)})

for A, H in ((TAIL, h_tail), (PM, h_pm), (PHASE1, h_seed), (SIGNER_RET, h_ret)):
    mu.hook_add(UC_HOOK_CODE, H, begin=A, end=A)
mu.hook_add(UC_HOOK_MEM_WRITE, h_memw, begin=LO, end=HI)

st = e.run(0xDB1CC, count=400_000_000, argstyle="nsign")
print("stopped:", st)
print("ctx:", hex(info.get("ctx", 0)), " seed: 0x%x" % info.get("seed", 0))
print("total writes into ctx region:", sum(1 for w in writes if w.get("ev") == "W"))
print("head calls:", " ".join("0x%04x" % h["w1"] for h in head))
print()
print("writes to ctx+0x30..0xbf (the 'd0' region) grouped by PC:")
seen = {}
for w in writes:
    if w.get("ev") != "W": continue
    if 0x30 <= w["off"] < 0xc0:
        seen.setdefault(w["pc"], []).append(w)
for pc in sorted(seen):
    ws = seen[pc]
    offs = sorted(set(x["off"] for x in ws))
    print("  pc=0x%06x  n=%4d  offsets %s" %
          (pc, len(ws), ("0x%x..0x%x" % (offs[0], offs[-1])) if len(offs) > 6
           else "[" + ",".join("0x%x" % o for o in offs) + "]"))
json.dump({"info_seed": info.get("seed"), "head": head,
           "phase1_d0": info.get("phase1_d0"),
           "posthead_d0": info.get("posthead_d0"),
           "working_18": info.get("working_18"),
           "writes": writes},
          open(os.path.join(HERE, "ctx_writes.json"), "w"), indent=1)
print("\nwrote ctx_writes.json")
