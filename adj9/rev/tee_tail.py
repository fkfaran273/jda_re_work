"""Decode the nSign TEE tail (0xdb7f4..0xdb1c8): the two encrypted state blobs
(adrp 0x155000 + ldrb flag 0xd92/0xd93/0xd94 = decrypt-once latches), the NEON
XOR-unmask at 0xdb830..0xdb850, the stlrb clear at 0xdb968..0xdb96c, and the
byte-compare at 0xdb970..0xdb98c that gates the epilogue. Prints what remains in
the unknown tail so the region (#0/#2/#4) input set can be named."""
import re

rows = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        rows.append((int(m.group(1), 16), m.group(2), m.group(3)))

print("=== 0xdb7f4..0xdb9dc region ===")
for a, m, o in rows:
    if 0xDB7F4 <= a <= 0xDB9DC:
        print("  0x%x  %-6s %s" % (a, m, o))
print("done")