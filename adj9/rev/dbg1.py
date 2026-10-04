# dbg1.py - why does branch_ids2 see no cmp lines: print the first 5 parsed lines.
import re

n = 0
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if not m:
        if n < 3:
            print("NOMATCH %r" % ln[:60])
        continue
    if n < 5:
        print("OK %r | %r | %r" % (m.group(1), m.group(2), m.group(3)[:40]))
    n += 1
print("total parsed:", n)