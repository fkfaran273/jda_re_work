"""decode_blobs2.py - fast blob decoder using context-window key association."""
import sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from decryptors import LIB

data = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
DATA_LO, DATA_HI = 0x151E00, 0x15540A
DELTA = 0x7E20

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

page = {}
events = []  # (idx, target_va, size, op_str)
for i, ins in enumerate(insns):
    m, ops = ins.mnemonic, ins.operands
    try:
        w = set(ins.regs_access()[1])
    except Exception:
        w = set()
    for r in w:
        if not (m in ("adrp", "adr", "add") and ops and r == ops[0].reg):
            page.pop(r, None)
    if m in ("adrp", "adr"):
        page[ops[0].reg] = ops[1].imm
    elif m == "add" and len(ops) == 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
        if ops[1].reg in page:
            page[ops[0].reg] = page[ops[1].reg] + ops[2].imm
    elif m.startswith(("ldr", "str")):
        if len(ops) >= 2 and ops[-1].type == ARM64_OP_MEM:
            b = ops[-1].mem.base
            d = ops[-1].mem.disp
            if b in page:
                tgt = page[b] + d
                if DATA_LO <= tgt < DATA_HI:
                    mn = ins.op_str.split()[0] if " " in ins.op_str else ""
                    sz = 16 if mn.startswith("q") else 8 if mn.startswith(("d", "x")) else 4 if mn.startswith(("w", "s")) else 1
                    events.append((i, tgt, sz, "%s %s" % (m, ins.op_str)))

# for each event, scan a window of +-12 insns for movi vN.8b #imm / eor wN,wN,#imm
keymap = {}
conflicts = set()
for i, tgt, sz, txt in events:
    keys = []
    for j in range(max(0, i - 12), min(len(insns), i + 13)):
        pj = insns[j]
        if pj.mnemonic == "movi" and len(pj.operands) == 2 and pj.operands[1].type == ARM64_OP_IMM:
            keys.append(pj.operands[1].imm & 0xFF)
        elif pj.mnemonic == "eor" and len(pj.operands) == 3 and pj.operands[2].type == ARM64_OP_IMM:
            keys.append(pj.operands[2].imm & 0xFF)
    if not keys:
        continue
    # majority key
    from collections import Counter
    k, cnt = Counter(keys).most_common(1)[0]
    for b in range(sz):
        t = tgt + b
        if t in keymap and keymap[t] != k:
            conflicts.add(t)
        keymap.setdefault(t, k)

print("# events %d, keymap %d, conflicts %d" % (len(events), len(keymap), len(conflicts)), file=sys.stderr)

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
