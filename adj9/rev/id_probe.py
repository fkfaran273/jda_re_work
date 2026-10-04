# id_probe.py - sweep the nSign frame ONCE for the distinctive pattern of the
# region construction: the only 'mov x8, #0x6dbb' + movk-chain + csel + bl
# #0xe293c fragment (0xdae30-0xdae78), so each writer block's store list can be
# anchored to one of the 14 id-ladder arms.
import re

seen = set()
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if not m:
        continue
    a, mn, op = int(m.group(1), 16), m.group(2), m.group(3)
    if mn in ("ldr", "ldp", "ldur") and re.search(r"#0x1[0-9a-f]{2}\b", op):
        key = (op.split("[")[1] if "[" in op else op)[:28]
        if key not in seen:
            seen.add(key)
            print("  0x%x  %s %s" % (a, mn, op))
print("done")