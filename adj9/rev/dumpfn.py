import os
import sys
import pickle

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402

SITES = [0xA0D74, 0xB9564, 0xD82C8, 0xDA2DC]


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)
    t = e.byname[".text"]
    lo, hi = t["addr"], t["addr"] + t["size"]
    off0 = e.vaddr_to_off(lo)
    code = e.data[off0:off0 + t["size"]]

    # callers map
    callers = {}
    for i in capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN).disasm(code, lo):
        pass

    for site in SITES:
        base = max(lo, site - 0x6000)
        off = e.vaddr_to_off(base)
        dis = list(md.disasm(e.data[off:e.vaddr_to_off(site) + 4], base))
        entry = None
        for i in reversed(dis):
            if i.mnemonic == "stp" and "x29" in i.op_str and "x30" in i.op_str:
                entry = i.address
                break
        print("\n" + "=" * 70)
        print("site 0x%x  enclosing fn entry ~0x%s" % (site, hex(entry) if entry else "?"))
        if not entry:
            continue
        o = e.vaddr_to_off(entry)
        n = (site - entry) // 4 + 40
        for i in md.disasm(e.data[o:o + n * 4], entry):
            mark = ""
            if i.address == site:
                mark = "   <<<<< SITE"
            if i.mnemonic == "bl":
                mark += "  (call 0x%x)" % i.operands[0].imm
            if any(k in i.op_str for k in ("#0x680", "#0x5c0", "#0x640", "#0x580")):
                mark += "  <JNI array>"
            print("  0x%x: %-8s %s%s" % (i.address, i.mnemonic, i.op_str, mark))
            if i.address > site + 64:
                break

        # callers of this function
        cs = []
        m2 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        m2.detail = True
        for i in m2.disasm(code, lo):
            if i.mnemonic == "bl" and i.operands and i.operands[0].imm == entry:
                cs.append(i.address)
        on = [a for a in cs if a in inset]
        print("  callers: %d total, %d on nSign path: %s" %
              (len(cs), len(on), [hex(a) for a in cs[:12]]))


if __name__ == "__main__":
    main()
