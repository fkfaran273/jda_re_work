# argdec.py - decode the JNI argument layout nSign expects, from its own first
# dereferences. JNIEnv* is x0: ldp x10,x8,[x0,#0x18] (env->functions table),
# then ldr x10,[x10] (first table slot reader), ldr x14,[x0] etc. Reconstruct
# which subsequent movk-chain ids land in which stack slots over the prologue,
# so the CALLER-side id->slot binding inside the VM can be named.
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "nsign_fn.log"
ins = []
for ln in open(path, encoding="utf-8", errors="replace"):
    m = re.match(r"0x([0-9a-f]+)\s+(\S+)\s+(.*)", ln)
    if m:
        ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
print("=== stores of the small-id constants (probes for NULL-arg detection) ===")
for a, m, o in ins:
    if m == "str" and re.search(r"w(zr|1[0-9])\b", o):
        print("  0x%x  str %s" % (a, o))
print("\n=== x0-based reads (arg positions) ===")
for a, m, o in ins:
    if m in ("ldr", "ldp", "ldur") and re.search(r"\[x0", o):
        print("  0x%x  %s %s" % (a, m, o))
print("\n=== calls with their preceding 3 insns (what is passed) ===")
for k in range(len(ins)):
    a, m, o = ins[k]
    if m == "bl" and 0xDAA00 < a < 0xDB200:
        print("  0x%x -> %s" % (a, o.split("#")[0]))
        for j in (3, 2, 1):
            if k - j >= 0:
                b, mm, oo = ins[k - j]
                print("      0x%x  %-4s %s" % (b, mm, oo))
print("done")