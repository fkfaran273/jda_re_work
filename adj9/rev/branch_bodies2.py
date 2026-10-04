# branch_bodies2.py - the id-compare ladder's arm bodies: from each arm's compare,
# the TAKEN branch target shows where that tag's field value is materialised;
# dump those arms in VA order so the per-field write side (desc #0..#10 content)
# can be read off the stores in each.
import re

ins = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
idx = {a: k for k, (a, _, _) in enumerate(ins)}
arms = [t for _, _, _, t in
        [(0, "", 0, s) for s in
         ["0xdae48 b.eq", "0xdaf0c b.eq", "0xdad80 b.eq", "0xdb014 b.eq",
          "0xdae10 b.eq", "0xdaee4 b.eq", "0xdad98 b.eq"]]]
arms = [0xdae48, 0xdaf0c, 0xdad80, 0xdb014, 0xdae10, 0xdaee4, 0xdad98,
        0xdb074, 0xdadbc, 0xdb120, 0xdb0b0, 0xdb0e8, 0xdb05c, 0xdadec,
        0xdaf44, 0xdaf68, 0xdb098, 0xdae60, 0xdb038, 0xdad80]
seen = set()
for t in arms:
    if t in seen:
        continue
    seen.add(t)
    k = idx[t]
    print("=== writes@0x%x ===" % t)
    n = 0
    while n < 30 and k < len(ins):
        a, m, o = ins[k]
        if m.startswith("b.") and "#0xdaad0" in o:
            print("  ... ends 0x%x %s %s" % (a, m, o))
            break
        print("  0x%x  %-4s %s" % (a, m, o))
        k += 1
        n += 1
print("done")