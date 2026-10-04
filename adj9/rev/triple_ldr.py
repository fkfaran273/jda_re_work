# triple_ldr.py - reconstruct the per-value (kind) triple bound at function entry
# into x26/x27/x28 for the 0xdae88-0xdaeac group, spelling out the ldr/ldp
# provenance: the group reads (sp+0x68) then locks (x26,x27), and the nSign frame
# field loop below merges (x26,x27,x28) into the per-call descriptor region.
import re

rows = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        rows.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("=== 0xdae80-0xdaec8: the descriptor-region lock ===")
for a, m, o in rows:
    if 0xDAE80 <= a <= 0xDAEC8:
        print("  0x%x  %-4s %s" % (a, m, o))
print("done")