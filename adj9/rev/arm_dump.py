# arm_dump.py - cut every if/else-if ARM in nSign (an arm ends at the 'cmp' or at the
# arm-start 'mov x9, #imm; [movk...]; cmp (x8|x10), x9'). Print each arm start and
# target so the structure (N ~ 46 kinds) is visible in one page.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))

print("%-8s %-8s %-22s %s" % ("cmp@", "op", "imm64-chain", "branch->"))
for k in range(len(ins)):
    a, m, o = ins[k]
    if m != "cmp":
        continue
    # walk back over mov/movk building the compare constant
    consts = []
    j = k - 1
    while j >= 0 and ins[j][1] in ("mov", "movk", "movz", "movn"):
        mm = re.match(r"(x\d+|w\d+),\s*#(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?", ins[j][2])
        if not mm:
            break
        r, v, sh = mm.group(1), int(mm.group(2), 16), int(mm.group(3) or 0)
        consts.append((r, v, sh))
        j -= 1
    # branch right after
    tgt = ""
    if k + 1 < len(ins) and ins[k + 1][1] in ("b.eq", "b.ne", "b.hi", "b.ls", "b.cs", "b.cc"):
        tgt = "0x%x %s" % (int(re.search(r"#(0x[0-9a-f]+)", ins[k + 1][2]).group(1), 16),
                           ins[k + 1][1])
    print("0x%-6x %-8s %-22s %s" % (a, o.split()[0], " ".join(
        "%s%s" % (hex(v), ("<<" + str(sh)) if sh else "") for _, v, sh in consts[:4][::-1]), tgt))