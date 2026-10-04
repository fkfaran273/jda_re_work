# cmp_case.py - reconstruct the BIG switch in nSign: the cmp-immediate ladders that
# select the per-field WRITE side. The dispatcher writes with 'str' to the return
# buffer at increasing offsets; print, in VA order, the (len,value source) of each
# state array slot it materialises.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))

# collect (mov reg,#imm ; movk...) chains followed by cmp -> case arms
print("=== 64-bit compare constants (case selectors incl. x8/x26) ===")
chains = []
cur = []
done = []
for a, m, o in ins:
    mm = re.match(r"(x\d+|w\d+|xzr|wzr),\s*#(0x[0-9a-f]+|\d+)", o)
    if m in ("mov", "movz", "movn", "movk") and mm:
        cur.append((mm.group(1), int(mm.group(2), 16)))
    elif m in ("cmp", "cmn") and mm:
        done.append((a, list(cur), mm.group(1)))
        cur = []
    elif m not in ("mov", "movz", "movn", "movk"):
        cur = []
for a, chain, reg in done:
    val = 0
    parts = {}
    for r, v in chain:
        if r == reg:
            parts.setdefault(r, []).append(v)
    print("  0x%x  cmp %s   chain=%s" % (a, reg, [(hex(v)) for _, v in chain][-3:]))