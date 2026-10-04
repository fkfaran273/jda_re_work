"""decode_blobs3.py - focused scan of the string-decrypt subsystem (0x10000-0x18000).
Pattern per state:
  adrp xN, 0x151000 (+ add xN, #off)  -> blob base B
  movi vM.8b/#16b, #key  (or mov wK, #key / eor imm)
  ldr  d/q vT, [xN, #off]  /  ldrb wT, [xN, #off]
  eor  vT.8b, vT, vM   /  eor wT, wT, wK / eor wT,wT,#imm
  str  back / strb back
  strb #1, [flag 0x1552xx]
Decode: file byte ^ key for each covered byte.
"""
import sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from decryptors import LIB

data = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
DELTA = 0x7E20
LO, HI = 0x10000, 0x18000

insns = list(md.disasm(data[LO:HI], LO))
print("# insns", len(insns), file=sys.stderr)

# track adrp/add bases
page = {}
vkeys = {}   # vector reg -> key
wkeys = {}   # w reg -> key
keymap = {}  # byte va -> (key, site)
opslog = []
for i, ins in enumerate(insns):
    m, ops = ins.mnemonic, ins.operands
    try:
        w = set(ins.regs_access()[1])
    except Exception:
        w = set()
    if m in ("adrp", "adr"):
        page[ops[0].reg] = ops[1].imm
    elif m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        if ops[1].reg in page:
            page[ops[0].reg] = page[ops[1].reg] + ops[2].imm
        else:
            page.pop(ops[0].reg, None)
    elif m == "movi" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
        vkeys[ops[0].reg] = ops[1].imm & 0xFF
    elif m in ("mov", "movz") and len(ops) == 2 and ops[1].type == ARM64_OP_IMM and ops[0].type == ARM64_OP_REG:
        rname = ins.reg_name(ops[0].reg)
        if rname.startswith("w"):
            wkeys[ops[0].reg] = ops[1].imm & 0xFF
    elif m.startswith(("ldr", "str")) and len(ops) >= 2 and ops[-1].type == ARM64_OP_MEM:
        b = ops[-1].mem.base
        d = ops[-1].mem.disp
        if b in page:
            tgt = page[b] + d
            if 0x151C00 <= tgt < 0x15540A:
                mn = ins.op_str.split()[0] if " " in ins.op_str else ""
                sz = 16 if mn.startswith("q") else 8 if mn.startswith(("d", "x")) else 4 if mn.startswith(("w", "s")) else 1
                opslog.append((ins.address, tgt, sz, m))
    elif m == "eor" and len(ops) == 3:
        # pair: dest reg's loaded target with key
        dest = ops[0].reg
        key = None
        if ops[2].type == ARM64_OP_IMM:
            key = ops[2].imm & 0xFF
        elif ops[2].type == ARM64_OP_REG and ops[2].reg in vkeys:
            key = vkeys[ops[2].reg]
        elif ops[2].type == ARM64_OP_REG and ops[2].reg in wkeys:
            key = wkeys[ops[2].reg]
        if key is not None:
            # find the last ldr target for this dest from opslog within short range
            for addr, tgt, sz, mm in reversed(opslog[-8:]):
                if mm.startswith("ldr"):
                    for b2 in range(sz):
                        keymap[tgt + b2] = (key, ins.address)
                    break

print("# keymap", len(keymap), file=sys.stderr)
out = {}
for va, (k, site) in keymap.items():
    fo = va - DELTA
    if 0 <= fo < len(data):
        out[va] = data[fo] ^ k

vs = sorted(out)
lines = []
cur = []
prev = None
for v in vs:
    if prev is not None and v != prev + 1:
        if cur:
            lines.append(cur)
        cur = []
    cur.append((v, out[v]))
    prev = v
if cur:
    lines.append(cur)
for ln in lines:
    if len(ln) < 2:
        continue
    s = "".join(chr(c) if 32 <= c < 127 else ("\x00" if c == 0 else "?") for _, c in ln)
    print("0x%x-0x%x: %s" % (ln[0][0], ln[-1][0], s))
