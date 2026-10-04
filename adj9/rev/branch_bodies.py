# branch_bodies.py - the id-compare ladder's arm bodies in ONE page each: from the
# arm-entry target through every call it makes (bl targets) plus the identity
# constants the arm materialises. The per-field WRITE side is inside exactly one
# of these callees per arm - which one is told by their descending call counts.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
ARMS = (0xdae48, 0xdb074, 0xdadbc, 0xdb120, 0xdb0b0, 0xdb0e8, 0xdb05c, 0xdadec,
        0xdaf44, 0xdaf68, 0xdb098, 0xdae60, 0xdb038, 0xdad80)


def at(a):
    return next(k for k, (x, _, _) in enumerate(ins) if x == a)


for t in ARMS:
    k = at(t)
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