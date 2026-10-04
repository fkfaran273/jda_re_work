# bhub.py - dump the WRITE side of every non-hub arm in the nSign ladder: from the
# arm-entry branch target to the next hub-branch (b #0xdaad0), listing the stores
# (str/stp/stlr/stur/strb) which materialise that field's state-array slots.
import re

ins = []
for ln in open("nsign_fn.log", encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
idx = {a: k for k, (a, _, _) in enumerate(ins)}

ARMS = {"0xdab4c": "0xdae48", "0xdab64": "0xdb074", "0xdab7c": "0xdadbc",
        "0xdabbc": "0xdb120", "0xdabd4": "0xdb0b0", "0xdabec": "0xdb0e8",
        "0xdac2c": "0xdb05c", "0xdac94": "0xdadec", "0xdacd4": "0xdaf44",
        "0xdacec": "0xdaf68", "0xdad10": "0xdb098", "0xdad28": "0xdae60",
        "0xdad40": "0xdb038", "0xdad58": "0xdad80"}
bad = [int(x, 16) for x in ARMS]
for a0, t0 in ARMS.items():
    a0i, t0i = int(a0, 16), int(t0, 16)
    k = idx[t0i]
    print("=== arm cmp@%s -> writes@%s ===" % (a0, t0))
    n = 0
    while k < len(ins) and n < 60:
        a, m, o = ins[k]
        if m.startswith("b.") and "#0xdaad0" in o:
            print("  ... ends 0x%x %s %s" % (a, m, o))
            break
        if m in ("str", "stp", "stlr", "stur", "strb", "bl", "adrp", "adr"):
            print("  0x%x  %-4s %s" % (a, m, o))
        k += 1
        n += 1
print("done")