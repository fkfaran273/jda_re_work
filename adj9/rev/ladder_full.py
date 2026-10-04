# ladder_full.py - FULL ordered arm table of the nSign id ladder: each arm's compare
# constant (assembled u64 from its mov/movk chain, with the chain printed) + the
# arm-entry branch target. x8 is the per-call tag; each arm compares it to one
# u64 built inline, then either exits to the hub (miss) or falls to a field writer.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))

pat = re.compile(r"0x([0-9a-f]+)\s+(mov|movk|movz)\s+(x\d+|w\d+),\s*#\s*(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?")
print("%-8s %-19s %s" % ("arm@", "compare-u64 (x8)", "taken->"))
narm = 0
for k in range(len(ins)):
    a, m, o = ins[k]
    mm = re.match(r"cmp\s+x8,\s*(x\d+|w\d+|xzr|wzr)", o)
    if m != "cmp" or not mm:
        continue
    src = mm.group(1)
    # walk back over mov/movk into src to assemble its u64
    v = 0
    j = k - 1
    parts = []
    while j >= 0:
        b, mm2, oo = ins[j]
        p = pat.match("0x%x %s %s" % (b, mm2, oo))
        if not p or p.group(3) != src:
            break
        val, sh = int(p.group(4), 16), int(p.group(5) or 0)
        v = (val << sh) if mm2 in ("mov", "movz") else \
            ((v & ~(0xFFFF << sh)) | ((val & 0xFFFF) << sh))
        parts.append((val, sh))
        j -= 1
    tgt = ""
    if k + 1 < len(ins) and ins[k + 1][1].startswith("b."):
        tgt = "0x%x %s" % (int(re.search(r"#(0x[0-9a-f]+)", ins[k + 1][2]).group(1), 16),
                           ins[k + 1][1])
    # only arms whose compare chain we could resolve (has mov-chain)
    print("0x%-6x %016x  %s" % (a, v & 0xFFFFFFFFFFFFFFFF, tgt))
    narm += 1
print("arms:", narm)
print("done")