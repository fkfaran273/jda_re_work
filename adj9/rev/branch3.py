# branch3.py - find the loops and big-frame writers INSIDE nSign's body. AArch64 loop
# back-edges look like: cbz/cbnz/tbnz + b back, or subs+ccmp loops. The two writer
# helpers are visible as 'str <reg>, [x?, <imm>]' with STA/STLR or plain str.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("insns:", len(ins))

print("=== backward branches (loops/retries) ===")
for a, m, o in ins:
    t = None
    if m in ("b", "bl"):
        mm = re.search(r"#(0x[0-9a-f]+)", o)
        if mm:
            t = int(mm.group(1), 16)
    elif m in ("cbz", "cbnz", "tbz", "tbnz"):
        mm = re.search(r"#(0x[0-9a-f]+)\s*$", o)
        if mm:
            t = int(mm.group(1), 16)
    if t is not None and t < a:
        print("  0x%x %-4s back -> 0x%x" % (a, m, t))

print("=== stores with small offsets (state writes) ===")
for a, m, o in ins:
    if m in ("str", "stp", "stlr") and re.search(r"#0x(1[0-9a-f]|2[0-9a-f]|3[0-9a-f]|[4-9a-f][0-9a-f])\b", o):
        print("  0x%x  %s %s" % (a, m, o))

print("=== stp x29,x30 pairs (nested call frames) ===")
for a, m, o in ins:
    if m == "stp" and "x29, x30" in o:
        print("  frame@0x%x %s" % (a, o))