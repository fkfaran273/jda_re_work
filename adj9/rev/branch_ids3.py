# branch_ids3.py - recover the per-switch GROUP identifiers (nSign's tag set) in the
# order the arms appear, with each taken target. The (index, tag, taken-arm) rows
# are what WH4 pairs to descriptor slots (#10 content positions), and the same rows
# tell us which KEY each taken arm binds (its claim field's UTF-8 value).
import re

ins = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln.rstrip("\r\n"))
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
pat = re.compile(r"0x[0-9a-f]+\s+(mov|movk|movz)\s+(x\d+|w\d+),\s*#\s*(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?")


def chain(k, reg):
    v = 0
    j = k - 1
    while j >= 0:
        m = pat.match("0x%x %s %s" % ins[j])
        if not m:
            break
        if m.group(2) != reg:
            break
        val, sh = int(m.group(3), 16), int(m.group(4) or 0)
        if m.group(1) in ("mov", "movz"):
            v = 0
        v = ((v & ~(0xFFFF << sh)) | ((val & 0xFFFF) << sh)) & 0xFFFFFFFFFFFFFFFF
        j -= 1
    return v


print("%-4s %-8s %-18s %s" % ("#", "cmp@", "tag-u64", "taken->"))
n = 0
for k in range(len(ins)):
    a, m, o = ins[k]
    mm = re.match(r"cmp\s+x8,\s*(x\d+|w\d+)", o)
    if m != "cmp" or not mm:
        continue
    v = chain(k, mm.group(1))
    tgt = ""
    if k + 1 < len(ins) and ins[k + 1][1].startswith("b."):
        tgt = "0x%x %s" % (int(re.search(r"#(0x[0-9a-f]+)", ins[k + 1][2]).group(1), 16),
                           ins[k + 1][1])
    print("%-4d 0x%-6x %016x  %s" % (n, a, v, tgt))
    n += 1
print("arms:", n)
print("done")