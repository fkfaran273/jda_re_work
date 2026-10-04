"""scan_rand.py - whole-text instruction index for libsigner.so + rand census.

Usage:
  python scan_rand.py census                # all bl rand/srand/time sites
  python scan_rand.py callers <target_hex>  # all bl sites targeting <target>
  python scan_rand.py backscan <va_hex>     # disasm 400 insns backwards from va (prologue hunt)
  python scan_rand.py xrefs_bl <start_hex> <end_hex>  # all bl targets inside range
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from decryptors import LIB
from elf import ELF

E = ELF(LIB)
t = E.byname[".text"]
TEXT_VA, TEXT_OFF, TEXT_SZ = t["addr"], t["offset"], t["size"]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

INSNS = []  # (addr, mnem, op)
_cache = HERE + "/_text_insns.txt"
if os.path.exists(_cache):
    for ln in open(_cache):
        a, m, o = ln.rstrip("\n").split("\t")
        INSNS.append((int(a, 16), m, o))
else:
    for ins in md.disasm(E.data[TEXT_OFF:TEXT_OFF + TEXT_SZ], TEXT_VA):
        INSNS.append((ins.address, ins.mnemonic, ins.op_str))
    with open(_cache, "w") as f:
        for a, m, o in INSNS:
            f.write("%x\t%s\t%s\n" % (a, m, o))
BYADDR = {a: (m, o) for a, m, o in INSNS}
IDX = {a: i for i, (a, m, o) in enumerate(INSNS)}

PLT = E.plt_map  # va -> name
BL_TARGET_NAME = {a: PLT.get(a, "") for a, m, o in INSNS if m == "bl"}


def parse_target(op):
    # "bl      #0x148d10"  or "bl      #0x8d6f4"
    t = op.replace("#", "").strip()
    try:
        return int(t, 16)
    except ValueError:
        return None


def main():
    cmd = sys.argv[1]
    if cmd == "census":
        for a, m, o in INSNS:
            if m == "bl":
                tgt = parse_target(o)
                nm = PLT.get(tgt)
                if nm in ("rand", "srand", "random", "time", "lrand48", "srand48", "rand_r"):
                    print("0x%x  bl %s (0x%x)" % (a, nm, tgt))
    elif cmd == "callers":
        tgt = int(sys.argv[2], 16)
        for a, m, o in INSNS:
            if m in ("bl", "b") and parse_target(o) == tgt:
                print("0x%x  %s 0x%x" % (a, m, tgt))
    elif cmd == "backscan":
        va = int(sys.argv[2], 16)
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 400
        i = IDX.get(va & ~3)
        if i is None:
            print("va not on instruction boundary")
            return
        for a, m, o in INSNS[max(0, i - n):i + 4]:
            nm = PLT.get(parse_target(o), "") if m in ("bl", "b") else ""
            print("0x%x  %-8s %-30s %s" % (a, m, o, ("; -> " + nm) if nm else ""))
    elif cmd == "xrefs_bl":
        lo, hi = int(sys.argv[2], 16), int(sys.argv[3], 16)
        for a, m, o in INSNS:
            if lo <= a < hi:
                nm = PLT.get(parse_target(o), "") if m in ("bl", "b") else ""
                print("0x%x  %-8s %-30s %s" % (a, m, o, ("; -> " + nm) if nm else ""))


if __name__ == "__main__":
    main()
