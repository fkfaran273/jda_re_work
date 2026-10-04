"""Dump full callees for the integer-crypto block: every `bl` target inside the
0xdb650..0xdb7f0 big frame region, so the candidate #2-#4 constructor sites can
be disassembled without guessing which call matters."""
import re

rows = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        rows.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("insns: %d (0x%x..0x%x)" % (len(rows), rows[0][0], rows[-1][0]))
print("=== bl inside 0xdb650..0xdb7f0 ===")
for a, m, o in rows:
    if m == "bl" and 0xDB650 <= a <= 0xDB7F0:
        print("  0x%x  bl %s" % (a, o.split(";", 1)[0]))
print("=== adrp inside 0xdb650..0xdb7f0 ===")
for a, m, o in rows:
    if m == "adrp" and 0xDB650 <= a <= 0xDB7F0:
        print("  0x%x  adrp %s" % (a, o))
print("done")