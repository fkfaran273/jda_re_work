"""decode_blobs.py - decode the XOR-obfuscated string/data area of libsigner.so.
One instruction sweep; for every ldr/str targeting the data segment, associate the
XOR key (immediate in the same or nearby instruction) and decrypt file bytes.
"""
import sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from decryptors import LIB

data = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

DATA_LO, DATA_HI = 0x151E00, 0x15540A
DELTA = 0x7E20  # file_off = va - DELTA for second RW segment

# single sweep, collect instructions
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
keymap = {}  # byte va -> key
# pre-index: for each load from data segment, find the eor that consumes it
# strategy: track per-register "last loaded data va"; when eor reg,reg,#imm seen, mark
loadva = {}  # reg -> (va, size)
for i, ins in enumerate(insns):
    m, ops = ins.mnemonic, ins.operands
    try:
        w = set(ins.regs_access()[1])
        r_ = set(ins.regs_access()[0])
    except Exception:
        w, r_ = set(), set()
    for r in w:
        if not (m in ("adrp", "adr", "add") and ops and r == ops[0].reg):
            page.pop(r, None)
    if m in ("adrp", "adr"):
        page[ops[0].reg] = ops[1].imm
        continue
    if m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        if ops[1].reg in page:
            page[ops[0].reg] = page[ops[1].reg] + ops[2].imm
        continue
    if m in ("ldr", "ldur", "ldrb", "ldur b") or (m.startswith("ldr")):
        if len(ops) >= 2 and ops[-1].type == ARM64_OP_MEM:
            b = ops[-1].mem.base
            d = ops[-1].mem.disp
            if b in page:
                tgt = page[b] + d
                if DATA_LO <= tgt < DATA_HI:
                    mn = ins.op_str.split()[0] if " " in ins.op_str else ""
                    sz = 16 if mn.startswith("q") else 8 if mn.startswith(("d", "x")) else 4 if mn.startswith(("w", "s")) else 1
                    loadva[ops[0].reg] = (tgt, sz)
    if m == "eor" and len(ops) == 3 and ops[2].type == ARM64_OP_IMM and ops[0].reg == ops[1].reg:
        if ops[0].reg in loadva:
            tgt, sz = loadva[ops[0].reg]
            k = ops[2].imm & 0xFF
            for i2 in range(sz):
                keymap[tgt + i2] = k
            loadva.pop(ops[0].reg)
    elif m == "eor" and len(ops) == 3 and ops[2].type == ARM64_OP_REG and ops[0].reg == ops[1].reg:
        # eor with vector register - key set by movi earlier; find nearest preceding movi on that reg
        for j in range(i - 1, max(0, i - 30), -1):
            pj = insns[j]
            if pj.mnemonic == "movi" and len(pj.operands) == 2 and pj.operands[0].reg == ops[2].reg and pj.operands[1].type == ARM64_OP_IMM:
                if ops[0].reg in loadva:
                    tgt, sz = loadva[ops[0].reg]
                    k = pj.operands[1].imm & 0xFF
                    for i2 in range(sz):
                        keymap[tgt + i2] = k
                    loadva.pop(ops[0].reg)
                break

print("# keymap", len(keymap), file=sys.stderr)

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
