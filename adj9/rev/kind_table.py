# kind_table.py - which READ of the emitted trace matches the per-value (kind)
# triple (x26,x27,x28) from nSign's entry block: the VA record layout for claims
# 0..46 is (idx<<32)|field_class, and the nSign frame's branch-limb for the 2nd
# group locks x26 to the second field of the pair it is about to compress.
import re

rows = []
for ln in open("branch_ids4.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(x\d+)\s+([0-9a-f]{16})\s+(0x[0-9a-f]+ \S+)?", ln)
    if m:
        rows.append((int(m.group(1), 16), m.group(2), int(m.group(3), 16),
                     (m.group(4) or "").strip()))
print("tag arms (cmp in x8/x9/x10 group) in VA order:")
for a, r, v, t in rows:
    print("  0x%x  cmp-reg=%-3s tag=%016x -> %s" % (a, r, v, t))
print("arms:", len(rows))
print("done")