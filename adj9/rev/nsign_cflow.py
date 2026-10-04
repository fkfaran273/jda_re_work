# nsign_cflow.py - decode the arithmetic the nSign body performs on the ARGUMENT
# ARRAY it was handed (x8 = per-call context, x26/x21 = identity words). The whole
# prologue x8/x9/x10 group (0xdaa00-0xdaac8) plus the hub region x8-vs-reg writes
# (0xdae24-0xdb12c) tells us which dwords of the VA/descriptor arrays are checked
# before the VA table run starts.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))

# minimal register-value machine for the immediate prologue only (no branches)
regs = {}


def setm(dst, v):
    regs[dst] = v & 0xFFFFFFFFFFFFFFFF


for a, m, o in ins:
    if a > 0xDAAD0:
        break
    mm = re.match(r"(x\d+|w\d+),\s*#(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?", o)
    if m in ("mov", "movz"):
        if mm:
            r, v, sh = mm.group(1), int(mm.group(2), 16), int(mm.group(3) or 0)
            setm(r, (v << sh) & 0xFFFFFFFFFFFFFFFF if "x" in r else v)
    elif m == "movk" and mm:
        r, v, sh = mm.group(1), int(mm.group(2), 16), int(mm.group(3) or 0)
        cur = regs.get(r, 0)
        mask = ~(0xFFFF << sh) & 0xFFFFFFFFFFFFFFFF
        regs[r] = ((cur & mask) | ((v & 0xFFFF) << sh)) & 0xFFFFFFFFFFFFFFFF
    elif m in ("add", "sub") and mm:
        r, v, sh = mm.group(1), int(mm.group(2), 16), int(mm.group(3) or 0)
        cur = regs.get(r, 0)
        regs[r] = ((cur + v) if m == "add" else (cur - v)) & 0xFFFFFFFFFFFFFFFF
    elif m == "ldr" and re.match(r"(x\d+),\s*\[x\d+\]", o):
        r = o.split(",")[0]
        regs[r] = "MEM"

print("=== prologue register state entering the first case split (0xdaaf0) ===")
for r in ["x%d" % i for i in range(29)] + ["w8", "w9", "w10", "w12"]:
    v = regs.get(r)
    if v is not None and v != 0:
        print("  %-4s = %s" % (r, hex(v) if isinstance(v, int) else v))
print("done")