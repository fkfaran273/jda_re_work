"""decode_blobs4.py v2 - precise per-register load->eor pairing over full text."""
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

insns = []
off = 0x1000
while off < 0x14da68:
    got = False
    for ins in md.disasm(data[off:0x14da68], off):
        got = True
        off = ins.address + ins.size
        insns.append(ins)
    if not got:
        off += 4
print("# insns", len(insns), file=sys.stderr)

page = {}
loadva = {}
vkeys = {}
wkeys = {}
keymap = {}
conf = {}

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

def mark(tgt, sz, k, site):
    for b in range(sz):
        t = tgt + b
        if t in keymap and keymap[t][0] != k:
            conf[t] = (keymap[t], k)
        keymap[t] = (k, site)

for ins in insns:
    m, ops = ins.mnemonic, ins.operands
    handled = False
    if m in ("adrp", "adr"):
        page[ops[0].reg] = ops[1].imm
        handled = True
    elif m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        if ops[1].reg in page:
            page[ops[0].reg] = page[ops[1].reg] + ops[2].imm
        else:
            page.pop(ops[0].reg, None)
        handled = True
    elif m in ("mov", "movz") and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
        rn = ins.reg_name(ops[0].reg)
        if rn.startswith("w") and 0 <= ops[1].imm <= 0xFF:
            wkeys[norm(ops[0].reg)] = ops[1].imm
        handled = True
    elif m == "movi" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
        vkeys[norm(ops[0].reg)] = ops[1].imm
        handled = True
    elif m.startswith(("ldr", "ldur")) and len(ops) >= 2 and ops[-1].type == ARM64_OP_MEM:
        b = ops[-1].mem.base
        d = ops[-1].mem.disp
        if b in page:
            tgt = page[b] + d
            if DATA_LO <= tgt < DATA_HI:
                mn = ins.op_str.split()[0] if " " in ins.op_str else ""
                loadva[norm(ops[0].reg)] = (tgt, szof(mn))
        handled = True
    elif m == "eor" and len(ops) == 3 and norm(ops[0].reg) == norm(ops[1].reg):
        key = None
        if ops[2].type == ARM64_OP_IMM:
            key = ops[2].imm & 0xFF
        elif norm(ops[2].reg) in vkeys:
            key = vkeys[norm(ops[2].reg)]
        elif norm(ops[2].reg) in wkeys:
            key = wkeys[norm(ops[2].reg)]
        if key is not None and norm(ops[0].reg) in loadva:
            tgt, sz = loadva[norm(ops[0].reg)]
            mark(tgt, sz, key, ins.address)
        loadva.pop(norm(ops[0].reg), None)
        handled = True
    if not handled:
        try:
            for r in ins.regs_access()[1]:
                page.pop(r, None)
                loadva.pop(norm(r), None)
        except Exception:
            pass

print("# keymap %d conflicts %d" % (len(keymap), len(conf)), file=sys.stderr)
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
