# branch_ids4.py - recover the per-switch GROUP identifiers (nSign's tag set) by
# copying ladder_fix.py's machine verbatim: replay the file once, track mov/movk
# constants per register, and emit (cmp VA, compared register, its u64, taken branch)
# at every cmp-with-reg. That table IS the arm list.
import re

ins = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
regs = {}


def setmov(dst, v, sh, kind):
    cur = regs.get(dst, 0)
    if kind in ("mov", "movz"):
        cur = 0
    if kind == "movn":
        regs[dst] = ((v << sh) ^ 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
        return
    mask = ~(0xFFFF << sh) & 0xFFFFFFFFFFFFFFFF
    regs[dst] = ((cur & mask) | ((v & 0xFFFF) << sh)) & 0xFFFFFFFFFFFFFFFF


def regval(r):
    return regs.get(r, 0)


print("%-8s %-8s %-17s %s" % ("cmp@", "cmp-reg", "compare-u64", "taken->"))
n = 0
for k, (a, m, o) in enumerate(ins):
    mm = re.match(r"(x\d+|w\d+|xzr|wzr),\s*#(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?", o)
    if m in ("mov", "movz", "movn", "movk") and mm:
        setmov(mm.group(1), int(mm.group(2), 16), int(mm.group(3) or 0), m)
    elif m in ("cmp", "ccmp"):
        parts = [p.strip() for p in o.split(",")]
        if len(parts) >= 2 and re.match(r"x\d+$", parts[1]):
            v = regval(parts[1])
            tgt = ""
            if k + 1 < len(ins) and ins[k + 1][1].startswith("b."):
                tgt = "0x%x %s" % (int(re.search(r"#(0x[0-9a-f]+)",
                                                 ins[k + 1][2]).group(1), 16),
                                   ins[k + 1][1])
            print("0x%-6x %-8s %016x  %s" % (a, parts[1], v, tgt))
            n += 1
        regs = {}
print("arms:", n)
print("done")