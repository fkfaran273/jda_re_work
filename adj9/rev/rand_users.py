"""rand_users.py - who calls rand() and srand() in libsigner.so?

The VM's RAND op (fin_vm2.py: OP_RAND = 0x148d10) resolves to libc rand(), and the
library also imports srand(). The per-call region (#0's 5 dwords + #2 + #4's 8)
is therefore a libc-PRNG stream. Offline reproduction needs:
  1. the SEED passed to srand (a second? a map hash? a pid?)
  2. the number/order of rand() draws (stream position)
  3. Bionic's exact rand() algorithm (emulated from the seed)

This prints every BL to the two PLT stubs with the enclosing function start (by
prologue scan) and the surrounding straight-line context, so the seed computation
and the region-fill loop become visible.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\\Apps\\Downloads\\com.penti.app\\extracted\\arm64\\lib\\arm64-v8a\\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

RAND, SRAND = 0x148D10, 0x148D30
text = E.byname[".text"]
t0, tsz, toff = text["addr"], text["size"], text["offset"]
code = E.data[toff:toff + tsz]

ins = list(MD.disasm(code, t0))
byaddr = {i.address: i for i in ins}

starts = set()
for i in ins:
    b = i.bytes
    # stp x29,x30,[sp,#-X]!  (C7 0F 00 A9 / DF 0B 00 A9 / 7D 23 00 A9 / FD 7B .. A9)
    if len(b) == 4 and b[3] == 0xA9 and b[2] in (0x0F, 0x0B, 0x23, 0x7B) \
            and (b[1] & 0x1F) == 29 and (b[0] & 0x1F) == 30:
        starts.add(i.address)
starts = sorted(starts)


def fn_of(va):
    import bisect
    k = bisect.bisect_right(starts, va) - 1
    return starts[k] if k >= 0 else None


print("prologues found: %d" % len(starts))
OUT = []
for insn in ins:
    if insn.mnemonic != "bl" or not insn.operands or insn.operands[0].type != 2:
        continue
    t = insn.operands[0].imm
    if t not in (RAND, SRAND):
        continue
    f = fn_of(insn.address)
    OUT.append((insn.address, t, f))

print("rand/srand call sites: %d" % len(OUT))
cur = None
for a, t, f in OUT:
    if f != cur:
        cur = f
        print("\n=== fn 0x%x ===" % f)
    nm = "rand" if t == RAND else "srand"
    print("  0x%x  bl %s" % (a, nm))

# for each call site, dump the 25 preceding instructions in the same function
for a, t, f in OUT:
    print("\n--- context 0x%x (%s), fn 0x%x ---"
          % (a, "rand" if t == RAND else "srand", f))
    for i in ins:
        if f <= i.address < a and a - i.address <= 120:
            ex = ""
            if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
                ex = "  ; -> %s" % (E.plt_map.get(i.operands[0].imm)
                                    or ("0x%x" % i.operands[0].imm))
            print("  0x%x  %-8s %s%s" % (i.address, i.mnemonic, i.op_str, ex))
print("\ndone")
json_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rand_users.json")
import json
json.dump([{"call": a, "fn": f, "which": "rand" if t == RAND else "srand"}
           for a, t, f in OUT], open(json_out, "w"), indent=1)
print("saved %s" % json_out)