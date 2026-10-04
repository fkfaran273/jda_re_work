"""vm_lift.py — lift fn 0x100094 (the stamp VM) to pseudo-ops.
Patterns are regular: PUSH(c)=mov w2,#c; bl 0x147630 / POP=bl 0x147734 /
arith=pop,pop,<op>,push / EMIT=bl 0x146ed8(len=w21, arg=w3) / rand=bl 0x148d10."""
import sys
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB

elf = open(LIB, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
LO, HI = 0x100094, 0x12aa48

insns = list(md.disasm(elf[LO:HI], LO))
OPS = {0x147630: "PUSH", 0x147734: "POP", 0x146ed8: "EMIT", 0x148d10: "RAND",
       0x147304: "LENQ", 0x1472e8: "OUTLEN", 0x146470: "OP6470", 0x146474: "OP6474",
       0x147a20: "OP7A20", 0x14784c: "CAP", 0x146558: "MKITER", 0x146650: "ITERNEXT",
       0x1476f8: "OP76F8", 0x147d3c: "MKDESC", 0x148a00: "free", 0x148b90: "calloc"}

def parse_imm(s):
    s = s.strip().lstrip("#")
    try:
        return int(s, 0)
    except ValueError:
        return None

prog = []
i = 0
last_w2 = None      # last immediate loaded into w2
last_w3 = None
pending = []        # recent ops for context
while i < len(insns):
    ins = insns[i]
    m = ins.mnemonic
    if m == "bl":
        t = int(ins.op_str.lstrip("#"), 16)
        name = OPS.get(t, "call_%x" % t)
        if name == "PUSH":
            prog.append("PUSH %s" % (hex(last_w2) if last_w2 is not None else "?"))
        elif name == "POP":
            prog.append("POP ->")
        elif name == "RAND":
            prog.append("RAND ->")
        elif name == "EMIT":
            prog.append("EMIT len=%s arg=%s" % (
                "w21" if True else "?", "w3"))
        else:
            prog.append("%s" % name)
        pending = []
    elif m in ("mov", "movz", "movk") and "," in ins.op_str:
        parts = [p.strip() for p in ins.op_str.split(",")]
        if len(parts) == 2 and parts[0] in ("w2", "x2") :
            v = parse_imm(parts[1])
            if v is not None:
                last_w2 = v
        if len(parts) == 2 and parts[0] in ("w3",):
            v = parse_imm(parts[1])
            if v is not None:
                last_w3 = v
    elif m in ("add", "sub", "eor", "and", "orr", "mul", "lsl", "lsr") :
        parts = [p.strip() for p in ins.op_str.split(",")]
        if len(parts) >= 3 and parts[0] == "w2":
            prog.append("arith %-4s %s" % (m, ",".join(parts[1:])))
    elif m in ("rev", "rev16", "b", "cbnz", "cbz", "ret", "cmp"):
        if m in ("b", "cbnz", "cbz"):
            prog.append("%s %s" % (m.upper(), ins.op_str))
    i += 1

print("total lifted ops:", len(prog))
open("vm_program.txt", "w").write("\n".join(prog))
# summary of op histogram
from collections import Counter
c = Counter(p.split()[0] for p in prog)
print(c.most_common(20))
print()
print("=== first 120 ops ===")
for p in prog[:120]:
    print("  ", p)
