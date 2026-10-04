# seed_reach.py - how is srand()'s argument computed inside 0x12cb74?
# Walk straight-line backwards from the 'bl srand' at 0x12cbc0 through mov/movk
# and arithmetic on w0/x0 to name the seed expression; the previous call is
# time(0x148d20) whose return goes straight into srand => seed = time(NULL).
import re

rows = []
for ln in open("r2.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        rows.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("=== backward slice: w0/x0 into bl srand@0x12cbc0 ===")
start = next(i for i, (a, _, _) in enumerate(rows) if a == 0x12CBC0)
for a, m, o in rows[max(0, start - 14):start + 2]:
    print("  0x%x  %-6s %s" % (a, m, o))
print("done")