"""Instrument the FULL native emit harness (emu_8d6f4) to capture the live
head mechanism and the final POST-HEAD d0.

Hooks
  0x1437ec phase-1 entry        -> w1 = seed
  0x1437c8 right after phase-1  -> x19 = ctx, snapshot phase-1 (ordinary) d0
  0x1441e4 tail wrapper         -> per head call: site (LR), w1, ctx
  0x144074 whitener             -> per head call: slot (x2), and the 16-halfword
                                   source region ctx+0x10..0x2f it XORs in
  0xdb1c4 signer return         -> final post-head d0
"""
import os, sys, json, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(os.path.join(HERE, "..", ".."))
import emu_8d6f4 as E
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

TAIL = 0x1441e4; PM = 0x1437c8; SIGNER_RET = 0xdb1c4
PHASE1 = 0x1437ec; WHIT = 0x144074; SEL = 0x143b20

def hw(buf, base, n): return [struct.unpack_from("<H", buf, base + 2 * i)[0] for i in range(n)]

e = E.Emu(); mu = e.mu
head = []; info = {}; cur = {}

def snap(addr, n=72): return hw(bytes(mu.mem_read(addr, 0x30 + 2 * n)), 0x30, n)

def h_tail(uc, addr, size, ud):
    w1 = uc.reg_read(UC_ARM64_REG_W1)
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    lr = uc.reg_read(UC_ARM64_REG_LR)
    rec = {"site": lr, "w1": w1, "ctx": x0}
    head.append(rec); info.setdefault("ctx", x0)
    # snapshot the whitener's INPUT region so we can see intermediate mutation
    try:
        rec["src_10_2f"] = hw(bytes(uc.mem_read(x0, 0x30)), 0x10, 16)
        rec["ctx_pre"] = hw(bytes(uc.mem_read(x0, 0x1a0)), 0, 0xd0)
    except Exception:
        pass

def h_whit(uc, addr, size, ud):
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    w1 = uc.reg_read(UC_ARM64_REG_W1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)
    if head:
        head[-1]["slot"] = x2
        head[-1]["whit_w1"] = w1

def h_pm(uc, addr, size, ud):
    ctx = uc.reg_read(UC_ARM64_REG_X19)
    info["ctx_pm"] = ctx
    info["phase1_d0"] = snap(ctx, 72)
    try:
        info["phase1_src_10_2f"] = hw(bytes(uc.mem_read(ctx, 0x30)), 0x10, 16)
        info["phase1_ctx"] = hw(bytes(uc.mem_read(ctx, 0x1a0)), 0, 0xd0)
    except Exception: pass

def h_seed(uc, addr, size, ud):
    info["seed"] = uc.reg_read(UC_ARM64_REG_W1)

def h_ret(uc, addr, size, ud):
    ctx = info.get("ctx")
    if ctx is not None:
        try:
            info["posthead_d0"] = snap(ctx, 72)
            blob = bytes(uc.mem_read(ctx, 0x100))
            info["d8"] = blob[0xd0:0xe0].hex()      # ctx+0xd0
            info["d9"] = blob[0xe0:0xf0].hex()      # ctx+0xe0
            info["ctx_00_2f"] = blob[0x00:0x30].hex()
            info["ctx_c0_cf"] = blob[0xc0:0xd0].hex()
        except Exception as ex: info["posthead_err"] = str(ex)

for A, H in ((TAIL, h_tail), (PM, h_pm), (PHASE1, h_seed),
             (SIGNER_RET, h_ret), (WHIT, h_whit)):
    mu.hook_add(UC_HOOK_CODE, H, begin=A, end=A)

st = e.run(0xDB1CC, count=400_000_000, argstyle="nsign")
print("stopped:", st)
print("seed (w1 to 0x1437ec): 0x%x" % info.get("seed", 0))
print("ctx(pm)  = 0x%x" % info.get("ctx_pm", 0))
print("ctx(head)= 0x%x" % info.get("ctx", 0))
print("num head calls:", len(head))
print()
print("idx  site      w1  slot  ctx")
for i, r in enumerate(head):
    print("  %2d  0x%06x  0x%04x  %3s  0x%x" %
          (i, r["site"], r["w1"], r.get("slot", "?"), r["ctx"]))

p1 = info.get("phase1_d0"); ph = info.get("posthead_d0")
if p1:
    print("\nPHASE-1 ORDINARY d0 (72 halfwords):")
    for r in range(0, 72, 12): print("  " + " ".join("%04x" % v for v in p1[r:r+12]))
if ph:
    print("\nPOST-HEAD d0 (72 halfwords):")
    for r in range(0, 72, 12): print("  " + " ".join("%04x" % v for v in ph[r:r+12]))
    if p1:
        d = [(i, "%04x" % p1[i], "%04x" % ph[i]) for i in range(72) if p1[i] != ph[i]]
        print("\nDIFF slots (idx, phase1 -> posthead), n=%d:" % len(d))
        for t in d: print("   ", t)
    print("\nHALFWORDS=" + " ".join("%04x" % v for v in ph))
    print("WORDS=" + " ".join("%08x" % (ph[2*i] | (ph[2*i+1] << 16)) for i in range(36)))

# did the whitener's source region mutate between head calls?
if head and "phase1_src_10_2f" in info:
    base = info["phase1_src_10_2f"]
    print("\nwhitener source ctx+0x10..0x2f per head call (vs phase-1):")
    for i, r in enumerate(head):
        s = r.get("src_10_2f")
        if s is None: continue
        same = (s == base)
        print("  %2d  w1=0x%04x  %s" % (i, r["w1"], "SAME as phase-1" if same else
              "DIFF: " + " ".join("%04x" % v for v in s)))

# full-ctx diff: what does the live run's ctx look like before each head call
# compared to the pure phase-1 snapshot? (finds intermediate mutations)
if "phase1_ctx" in info:
    base = info["phase1_ctx"]
    print("\nfull-ctx (0x00..0xcf) diff vs phase-1, per head call:")
    for i, r in enumerate(head):
        c = r.get("ctx_pre")
        if c is None: continue
        d = [(j, "%04x" % base[j], "%04x" % c[j]) for j in range(0xd0) if base[j] != c[j]]
        if not d:
            print("  %2d  w1=0x%04x  identical to phase-1" % (i, r["w1"]))
        else:
            lo = d[0][0]; hi = d[-1][0]
            print("  %2d  w1=0x%04x  %d changed, span +0x%x..+0x%x" % (i, r["w1"], len(d), lo, hi))

print("d8 (ctx+0xd0):", info.get("d8"))
print("d9 (ctx+0xe0):", info.get("d9"))
print("ctx+0x00..0x2f:", info.get("ctx_00_2f"))
print("ctx+0xc0..0xcf (free-slot template):", info.get("ctx_c0_cf"))

json.dump({"seed": info.get("seed"), "ctx": info.get("ctx"),
           "head": head, "phase1_d0": p1, "posthead_d0": ph,
           "d8": info.get("d8"), "d9": info.get("d9"),
           "ctx_00_2f": info.get("ctx_00_2f"), "ctx_c0_cf": info.get("ctx_c0_cf"),
           "stopped": st},
          open(os.path.join(HERE, "posthead_result.json"), "w"), indent=1)
print("\nwrote posthead_result.json")
