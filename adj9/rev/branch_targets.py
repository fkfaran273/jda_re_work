# branch_targets.py - which functions the case-ladder arms CALL (the bl targets at
# the end of each arm): the read/write primitives of the native state arrays.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
addrs = {a for a, _, _ in ins}
print("insns:", len(ins))

# function entries = BL targets inside this range
blt = set()
for a, m, o in ins:
    if m == "bl":
        mm = re.search(r"#(0x[0-9a-f]+)", o)
        if mm:
            t = int(mm.group(1), 16)
            if 0xD0000 <= t <= 0xE0000:
                blt.add(t)
print("BL targets inside nSign span:", sorted("0x%x" % t for t in blt))
print("\n=== what each arm calls (arm start -> target list) ===")
cur = None
buf = []
for a, m, o in ins:
    if m == "b.ne" and re.search(r"#0xdaac8", o):
        if cur:
            print("  0x%x: %s" % (cur, buf))
        cur = a
        buf = []
    if cur is not None and m == "bl":
        buf.append("0x%x(%s)" % (int(re.search(r"#(0x[0-9a-f]+)", o).group(1), 16), o.split("#")[0]))
print("  0x%x: %s" % (cur, buf) if cur else "")
print("done")