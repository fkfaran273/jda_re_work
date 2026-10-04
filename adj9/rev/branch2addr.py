# branch2addr.py - scan ONE function body for a specific (mnemonic, operand-value)
# pattern: here, "bl #..." that jumps BACKWARD (loops) + back-to-back calls.
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
print("=== backward bl targets (loops) ===")
for a, m, o in ins:
    if m == "bl":
        t = int(o.split("#")[1].split()[0], 16)
        if t < a:
            print("  loop 0x%x -> 0x%x" % (a, t))
print("=== bl pairs (back-to-back calls) ===")
for k in range(len(ins) - 3):
    if ins[k][1] == "bl" and ins[k + 2][1] == "bl" and \
            abs(ins[k][0] - ins[k + 2][0]) <= 16:
        print("  0x%x -> %s ; 0x%x -> %s" % (ins[k][0], ins[k][2],
                                             ins[k + 2][0], ins[k + 2][2]))
print("=== movz #len constants into likely descriptor-length slots ===")
for a, m, o in ins:
    if m in ("movz", "mov") and re.search(r"#(0x)?(24|5b|5a|168|1f6|211|212|1e8)\b", o):
        print("  0x%x  %s %s" % (a, m, o))