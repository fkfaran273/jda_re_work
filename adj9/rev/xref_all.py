"""xref_all.py - whole-binary bl xref: list callers of given targets, or
group all bl sites. Also detect svc/br/blr sites and mrs reads."""
import sys, os, struct
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

LIB = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
elf = open(LIB, "rb").read()
CODE_END = 0x148e60  # end of executable mapping per headers used elsewhere

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

callers = defaultdict(list)   # target -> [(pc)]
blrs = []                     # (pc) indirect
svcs = []
mrss = []
pos = 0
ins_count = 0
while pos < CODE_END:
    got = False
    for ins in md.disasm(elf[pos:CODE_END], pos):
        got = True
        ins_count += 1
        m = ins.mnemonic
        if m == "bl":
            callers[ins.operands[0].imm].append(ins.address)
        elif m in ("blr", "br"):
            blrs.append((ins.address, m))
        elif m == "svc":
            svcs.append(ins.address)
        elif m == "mrs":
            mrss.append((ins.address, ins.op_str))
        pos = ins.address + ins.size
    if not got:
        pos += 4  # resync past data pool / bad word

if __name__ == "__main__":
    if sys.argv[1] == "callers":
        for a in sys.argv[2:]:
            t = int(a, 16)
            cl = callers.get(t, [])
            print("target 0x%x: %d callers" % (t, len(cl)))
            for pc in cl:
                print("   0x%x" % pc)
    elif sys.argv[1] == "counts":
        import json
        items = sorted(callers.items(), key=lambda kv: -len(kv[1]))
        for t, cl in items[:80]:
            print("0x%-8x %d" % (t, len(cl)))
    elif sys.argv[1] == "svc":
        print("svc sites:", ["0x%x" % x for x in svcs])
    elif sys.argv[1] == "mrs":
        for pc, s in mrss:
            print("0x%x  mrs %s" % (pc, s))
