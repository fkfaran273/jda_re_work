"""vm_cfg.py — build the REAL control-flow graph of clean fn 0x100094,
strip flattened-token noise, and print the executable program skeleton.

The fn is un-flattened clean code: real loops via b/cbz/cbnz to nearby labels.
Token-mov noise lives only in helper fns, but the stamp fn also calls many
one-shot CAS decrypt blocks. Here: CFG via recursive descent from 0x100094,
dedupe, order blocks, and annotate each block with its REAL ops
(anything that is not mov/movk constant-materialization of x8..x28)."""
import sys
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
LO, HI = 0x100094, 0x12aa48
insns = list(md.disasm(elf[LO:HI], LO))
idx = {i.address: k for k, i in enumerate(insns)}

def parse_t(s):
    try: return int(s.lstrip("#"), 16)
    except (ValueError, AttributeError): return None

# ---- recursive descent ----
blocks = {}          # start -> list of insns
worklist = [LO]
seen_starts = set()
TERM = {"b", "ret", "cbz", "cbnz", "tbz", "tbnz"}
while worklist:
    start = worklist.pop()
    if start in seen_starts or start not in idx:
        continue
    seen_starts.add(start)
    k = idx[start]
    blk = []
    while k < len(insns):
        i = insns[k]
        blk.append(i)
        m = i.mnemonic
        if m == "b":
            t = parse_t(i.op_str)
            if t and LO <= t < HI:
                worklist.append(t)
            blocks[start] = blk
            break
        if m.startswith("b."):
            t = parse_t(i.op_str)
            if t and LO <= t < HI:
                worklist.append(t)
            worklist.append(i.address + 4)      # fall-through
            blocks[start] = blk
            break
        if m == "ret":
            blocks[start] = blk
            break
        if m in ("cbz", "cbnz", "tbz", "tbnz"):
            # last operand is the target
            t = parse_t(i.op_str.split(",")[-1])
            if t and LO <= t < HI:
                worklist.append(t)
            worklist.append(i.address + 4)      # fall-through
            blocks[start] = blk
            break
        if m == "bl":
            # call: continue to next (assume returns)
            pass
        k += 1
    else:
        blocks[start] = blk

print("blocks: %d  (starts %s .. %s)" % (len(blocks), hex(min(blocks)), hex(max(blocks))))

# ---- noise classifier ----
TOKEN_REGS = {"x8","x9","x10","x11","x12","x13","x14","x15","x16","x17",
              "x19","x20","x21","x22","x23","x24","x25","x26","x27","x28",
              "w8","w9","w10","w11","w12","w13","w14","w15","w16","w17",
              "w19","w20","w21","w22","w23","w24","w25","w26","w27","w28"}
def is_noise(i):
    if i.mnemonic in ("mov", "movz", "movk"):
        d = i.op_str.split(",")[0].strip()
        return d in TOKEN_REGS
    if i.mnemonic == "cmp" and i.op_str.replace(" ", "").split(",")[0] in ("x8","x9","x10","x15"):
        # state-machine comparisons
        a = i.op_str.replace(" ", "")
        if re_token.match(a): return True
        return False
    if i.mnemonic in ("b.eq", "b.ne", "b.le", "b.lt", "b.gt", "b.ge", "b.hi", "b.lo", "b.hs", "b.ls"):
        return False  # keep branches (CFG)
    if i.mnemonic == "b":
        return False
    if i.mnemonic in ("csel",):
        d = i.op_str.split(",")[0].strip()
        return d in TOKEN_REGS
    return False
import re as _re
re_token = _re.compile(r"^[xw](8|9|1[0-5]|1[6-9]|2[0-8]),#[0-9a-fx]+")

# order blocks by start
starts = sorted(blocks)
real = 0
lines = []
for s in starts:
    blk = blocks[s]
    keep = [i for i in blk if not is_noise(i)]
    if not keep:
        continue
    real += len(keep)
    lines.append("blk 0x%06x (%d insns, %d real)" % (s, len(blk), len(keep)))
    for i in keep:
        lines.append("   %06x: %-8s %s" % (i.address, i.mnemonic, i.op_str))
open("vm_real.txt", "w").write("\n".join(lines))
print("real ops kept: %d -> vm_real.txt (%d lines)" % (real, len(lines)))

# block-size histogram: how many are big (real work) vs tiny
big = [(s, len(blocks[s])) for s in starts if len(blocks[s]) > 20]
print("blocks > 20 insns: %d" % len(big))
for s, n in big[:12]:
    print("   0x%x: %d insns" % (s, n))
