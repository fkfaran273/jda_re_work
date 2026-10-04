# loads.py - every load/store-ish mnemonic inside the nSign frame, in VA order,
# with the destination register. The descriptor table is loaded through a small
# handful of address calculations; the pattern of ldr destinations over VA order
# shows where #0/#2/#4 enter the core.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("counts:")
from collections import Counter
c = Counter(m for _, m, _ in ins)
for m, n in c.most_common(20):
    print("  %-8s %d" % (m, n))
print("\n=== first ldr/ldp run (prologue region loads) ===")
for a, m, o in ins[:60]:
    if m in ("ldr", "ldp", "ldur", "adrp", "adr"):
        print("  0x%x  %s %s" % (a, m, o))
print("done")