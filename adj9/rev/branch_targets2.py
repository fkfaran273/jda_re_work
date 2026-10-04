# branch_targets2.py - FIRST, the hub: every 'b #0xdaad0' in nSign is the miss arm
# of a case. Print every b.eq->hub pair's arm, in order, as (arm_va, arm_bytes)
# with its case constant, so each case's WRITE side can be dumped next.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("insns:", len(ins))
print("=== arms (b.eq -> HUB 0xdaad0 means: kind id did NOT match here) ===")
for k in range(len(ins)):
    a, m, o = ins[k]
    if m == "b.eq" and "#0xdaad0" in o and k + 1 < len(ins):
        b, mm, oo = ins[k + 1]
        print("  arm@0x%x next=0x%x %s %s" % (a, b, mm, oo))
print("done")