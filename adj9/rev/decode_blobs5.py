"""decode_blobs5.py - block-wise decode of the string-decrypt subsystem.
Blocks are delimited by 'b 0x10594' (the get-string dispatcher tail-call).
Each block: adrp/add bases, movi/mov key(s), ldr/ldrb blob, eor, str back.
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
DATA_LO, DATA_HI = 0x151000, 0x15540A
DISPATCH = 0x10594

insns = list(md.disasm(data[0x10000:0x17000], 0x10000))

def norm(reg):
    if ARM64_REG_D0 <= reg <= ARM64_REG_D31:
        return ARM64_REG_V0 + (reg - ARM64_REG_D0)
    if ARM64_REG_S0 <= reg <= ARM64_REG_S31:
        return ARM64_REG_V0 + (reg - ARM64_REG_S0)
    if ARM64_REG_Q0 <= reg <= ARM64_REG_Q31:
        return ARM64_REG_V0 + (reg - ARM64_REG_Q0)
    if ARM64_REG_W0 <= reg <= ARM64_REG_W30:
        return ARM64_REG_X0 + (reg - ARM64_REG_W0)
    if reg == ARM64_REG_WZR:
        return ARM64_REG_XZR
    return reg

def szof(mn):
    if mn.startswith("q"): return 16
    if mn.startswith(("d", "x")): return 8
    if mn.startswith("w"): return 4
    if mn.startswith("h"): return 2
    if mn.startswith("b"): return 1
    return 1

# split into blocks at 'b DISPATCH'
blocks = []
cur = []
for ins in insns:
    cur.append(ins)
    if ins.mnemonic == "b" and ins.operands[0].imm == DISPATCH:
        blocks.append(cur)
        cur = []
if cur:
    blocks.append(cur)
print("# blocks", len(blocks), file=sys.stderr)

keymap = {}
conf = {}
nblob = 0
for blk in blocks:
    page = {}
    vkeys = {}
    wkeys = {}
    loads = []  # (reg, tgt, sz)
    marks = []
    for ins in blk:
        m, ops = ins.mnemonic, ins.operands
        if m in ("adrp", "adr"):
            page[ops[0].reg] = ops[1].imm
        elif m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
            if ops[1].reg in page:
                page[ops[0].reg] = page[ops[1].reg] + ops[2].imm
        elif m in ("mov", "movz") and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            rn = ins.reg_name(ops[0].reg)
            if rn.startswith("w") and 0 <= ops[1].imm <= 0xFF:
                wkeys[norm(ops[0].reg)] = ops[1].imm
        elif m == "movi" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            vkeys[norm(ops[0].reg)] = ops[1].imm
        elif m.startswith(("ldr", "ldur")) and len(ops) >= 2 and ops[-1].type == ARM64_OP_MEM:
            b = ops[-1].mem.base
            d = ops[-1].mem.disp
            if b in page:
                tgt = page[b] + d
                if DATA_LO <= tgt < DATA_HI:
                    mn = ins.op_str.split()[0] if " " in ins.op_str else ""
                    loads.append((norm(ops[0].reg), tgt, szof(mn)))
        elif m == "eor" and len(ops) == 3 and norm(ops[0].reg) == norm(ops[1].reg):
            key = None
            if ops[2].type == ARM64_OP_IMM:
                key = ops[2].imm & 0xFF
            elif norm(ops[2].reg) in vkeys:
                key = vkeys[norm(ops[2].reg)]
            elif norm(ops[2].reg) in wkeys:
                key = wkeys[norm(ops[2].reg)]
            # pair with the matching load for this reg (last one)
            for j in range(len(loads) - 1, -1, -1):
                if loads[j][0] == norm(ops[0].reg):
                    if key is not None:
                        _, tgt, sz = loads[j]
                        for b2 in range(sz):
                            t = tgt + b2
                            if t in keymap and keymap[t] != key:
                                conf[t] = (keymap[t], key)
                            keymap[t] = key
                        nblob += 1
                    break
print("# blobs marked %d, keymap %d, conflicts %d" % (nblob, len(keymap), len(conf)), file=sys.stderr)

out = {}
for va, k in keymap.items():
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
