# switch_map.py - find EVERY 'b.eq → target' whose source compared a value against
# an inline constant, restricted to code reachable through the case arms. The
# goal: the label enum behind nSign's field switch. Print arm list as
# (case_addr, cmp_value, arm_target).
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

# walk back from each 'b.eq #T': the cmp source might be the immediate prior cmp
# (compiler merges same-value checks), so record the (cmp_reg, imm) pairs seen
# along with whether they hit the hub 0xdaad0 (common exit) or a field writer.
print("=== b.eq arms NOT to the hub ===")
for k in range(len(ins) - 1):
    a, m, o = ins[k]
    if m == "b.eq":
        t = int(re.search(r"#(0x[0-9a-f]+)", o).group(1), 16)
        if t == 0xDAAD0:
            continue
        # find nearest cmp above (up to 40 back)
        src = None
        for j in range(k - 1, max(k - 40, -1), -1):
            if ins[j][1] in ("cmp", "ccmp"):
                src = ins[j]
                break
        print("  0x%x b.eq -> 0x%x   nearest %s %s" % (a, t, src[1] if src else "?",
                                                       src[2] if src else ""))