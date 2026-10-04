# dbg2.py - find how the working scripts (ladder_fix) parse cmp lines, and whether
# branch_ids3's patterns fail on operand form.
import re

print("plain:", bool(re.match(r"cmp\s+x8,\s*(x\d+|w\d+)", "cmp      x8, x9")))
for ln2 in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln2.rstrip("\r\n"))
    if m and m.group(2) == "cmp" and "x8" in m.group(3)[:6]:
        print(repr(m.group(3)))
        print("match:", bool(re.match(r"cmp\s+x8,\s*(x\d+|w\d+)", "cmp " + m.group(3))))
        break