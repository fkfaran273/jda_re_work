# branch4.py - the id-compare ladder is ARMED by value: the nSign expects each map
# KEY as a 64-bit hash. Build the arm table: collect mov(x9)+movk-chain values,
# and associate each arm-start with the map key position by reading the SECOND read
# of the probing array (the [x?, #imm] fetch before the chain).
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("insns:", len(ins))

# find ldr x?, [x?, #imm] inside the ladder region then the hash chain
print("=== ldr probes inside the 0xdab00-0xdad80 ladder ===")
for a, m, o in ins:
    if 0xDAA00 <= a < 0xDAD80 and m == "ldr":
        print("  0x%x  ldr %s" % (a, o))