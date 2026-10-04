#!/usr/bin/env python3
"""Recover the O-LLVM control-flow-flattening state map.

Each flattened block ends by writing the next dispatcher state into a register
and jumping back to the dispatcher; the dispatcher is a chain of
    mov/movk <const into xR> ; cmp xS, xR ; b.eq <block>
We track contiguous mov/movk chains per register to recover the constants, then
pair each constant with the branch target.
"""
import struct, sys, collections
from capstone import *
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

FN = "../../extracted/arm64/lib/arm64-v8a/libsigner.so"
d = open(FN, "rb").read()

# --- section table -> .text range -----------------------------------------
e_shoff, = struct.unpack_from("<Q", d, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3a)
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", d, o)
    secs.append((name, typ, off, size, addr))
sh = secs[e_shstrndx]
def nm(n):
    b = d[sh[2] + n:]
    return b[:b.index(0)].decode()
TEXT = next((s for s in secs if nm(s[0]) == ".text"), None)
name, typ, toff, tsize, taddr = TEXT
print(".text va 0x%x size %d" % (taddr, tsize))

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

KNOWN = {}          # reg -> int (fully known constant)
PART = {}           # reg -> (value, mask) partial
states = collections.defaultdict(set)   # state const -> {target}
n_cmp = 0

code = d[toff:toff + tsize]
prev_reg = None
for ins in md.disasm(code, taddr):
    mn = ins.mnemonic
    ops = ins.operands
    if mn in ("mov", "movz") and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
        KNOWN[ops[0].reg] = ops[1].imm & 0xFFFFFFFFFFFFFFFF
        PART.pop(ops[0].reg, None)
        continue
    if mn == "movk" and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
        shift = 0
        if len(ops) >= 3 and ops[2].type == ARM64_OP_IMM:
            shift = ops[2].imm
        v = ops[1].imm & 0xFFFF
        if ops[0].reg in KNOWN:
            cur = KNOWN[ops[0].reg]
        elif ops[0].reg in PART:
            cur, _ = PART[ops[0].reg]
        else:
            cur = 0
        KNOWN[ops[0].reg] = (cur & ~(0xFFFF << shift)) | (v << shift)
        continue
    if mn in ("adr", "adrp"):
        for r in (KNOWN, PART):
            r.pop(ops[0].reg if ops else 0, None)
        continue
    if mn == "cmp" and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        n_cmp += 1
        other = ops[1]
        if other.type == ARM64_OP_REG and other.reg in KNOWN:
            prev_reg = KNOWN[other.reg]
        else:
            prev_reg = None
        continue
    if mn == "b.eq" and prev_reg is not None and ops and ops[0].type == ARM64_OP_IMM:
        states[prev_reg].add(ops[0].imm)
        prev_reg = None
        continue
    if mn.startswith("b.") or mn in ("b", "ret", "blr", "br"):
        prev_reg = None
        continue
    # any other instruction writing a register invalidates it
    if ops and ops[0].type == ARM64_OP_REG:
        KNOWN.pop(ops[0].reg, None)
        PART.pop(ops[0].reg, None)
    prev_reg = None

print("cmp insns:", n_cmp)
print("distinct state constants:", len(states))
multi = {k: v for k, v in states.items() if len(v) > 1}
print("states with >1 target:", len(multi))
tot = sum(len(v) for v in states.values())
print("total (state,target) pairs:", tot)
json_out = {("0x%016x" % k): sorted(v) for k, v in states.items()}
import json
json.dump(json_out, open("ollvm_states.json", "w"), indent=0)
print("wrote ollvm_states.json")
for k in list(states)[:8]:
    print("  0x%016x -> %s" % (k, ["0x%x" % t for t in sorted(states[k])]))
