# emit_wr.py - the id-compare ladder's arm bodies are per-FIELD serializers: each
# arm-entry branch jumps to a WRITE block that materialises one descriptor slot
# (#0..#10 content) from the per-call value list. Dump every TAKEN arm's write
# block in VA order so the desc->field mapping for the region #0/#2/#4 falls out
# (which data pointer/which constant each desc slot is built from).
import re

ins = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
idx = {a: k for k, (a, _, _) in enumerate(ins)}
arms = [0xdae48, 0xdaf0c, 0xdad80, 0xdb014, 0xdae10, 0xdaee4, 0xdad98,
        0xdb074, 0xdadbc, 0xdb120, 0xdb0b0, 0xdb0e8, 0xdb05c, 0xdadec,
        0xdaf44, 0xdaf68, 0xdb098, 0xdae60, 0xdb038]
seen = set()
for t in arms:
    if t in seen:
        continue
    seen.add(t)
    k = idx[t]
    print("=== writes@0x%x ===" % t)
    n = 0
    while n < 45 and k < len(ins):
        a, m, o = ins[k]
        if m.startswith("b.") and "#0xdaad0" in o:
            print("  ... ends 0x%x %s %s" % (a, m, o))
            break
        print("  0x%x  %-4s %s" % (a, m, o))
        k += 1
        n += 1
print("done")