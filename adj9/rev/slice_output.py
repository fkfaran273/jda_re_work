"""Backward-slice from the SetByteArrayRegion site (0x9e880).

1. Locate the function containing 0x9e880 (scan back for the prologue).
2. Dump it, marking every store to [x29,#-8] (envelope buffer ptr) and
   [x29,#-0xc] (length), so we know where the buffer value comes from.
3. Find callers of the NewByteArray wrapper at 0x9e55c and their size args.
"""
import os
import sys
import pickle

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
from decryptors import LIB

SITE = 0x9E880


def disasm_at(e, md, va, n):
    off = e.vaddr_to_off(va)
    return list(md.disasm(e.data[off:off + n * 4], va))


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)

    # --- 1. find the function entry: scan backwards for a prologue
    va = SITE
    entry = None
    while va > SITE - 0x800:
        va -= 4
        i = disasm_at(e, md, va, 1)[0]
        # stp x29, x30, [sp, #-imm]!  OR  sub sp, sp, #imm after stp
        if (i.mnemonic == "stp" and "x29" in i.op_str and "x30" in i.op_str
                and "sp" in i.op_str):
            entry = va
            break
    print("SetByteArrayRegion site 0x%x; enclosing function entry ~0x%x" % (SITE, entry))

    # --- 2. dump function, mark writes to x29-8 / x29-0xc and key ops
    if entry:
        n = (SITE - entry) // 4 + 24
        code = disasm_at(e, md, entry, n)
        print("\n=== function body (entry..site+96B) ===")
        for i in code:
            line = "0x%x: %-8s %s" % (i.address, i.mnemonic, i.op_str)
            flags = []
            if "[x29, #-8]" in i.op_str and i.mnemonic in ("str", "stur", "stp"):
                flags.append("<== writes ENV BUF ptr [x29,-8]")
            if "[x29, #-0xc]" in i.op_str and i.mnemonic in ("str", "stur", "stp"):
                flags.append("<== writes ENV LEN [x29,-0xc]")
            if i.mnemonic == "blr":
                flags.append("<<< indirect call")
            if i.address == SITE:
                flags.append("<<<<< OUTPUT WRITE")
            onpath = "" if i.address in inset else "  [not on nSign path]"
            print("  %s%s%s" % (line, "  " + "; ".join(flags) if flags else "", onpath))
            if i.address > SITE + 48:
                break

    # --- 3. callers of NewByteArray wrapper (function entry ~0x9e55c)
    # first confirm wrapper entry
    va = 0x9E580
    wrap = None
    while va > 0x9E580 - 0x200:
        va -= 4
        i = disasm_at(e, md, va, 1)[0]
        if i.mnemonic == "stp" and "x29" in i.op_str and "x30" in i.op_str:
            wrap = va
            break
    print("\nNewByteArray wrapper entry ~0x%x" % wrap)
    if wrap:
        # scan the whole nSign instruction set for `bl 0x<wrap>`
        hits = []
        for a in sorted(inset):
            if a < 0x10000:  # quick filter, wrapper callers are in hot region too
                continue
            i = disasm_at(e, md, a, 1)[0]
            if i.mnemonic == "bl" and i.operands and i.operands[0].imm == wrap:
                hits.append(a)
        print("callers of NewByteArray wrapper on nSign path: %s" % [hex(h) for h in hits])
        for a in hits:
            print("\n  context for caller @ 0x%x:" % a)
            for i in disasm_at(e, md, a - 32, 12):
                extra = "  <<<" if i.address == a else ""
                txt = "0x%x: %-8s %s%s" % (i.address, i.mnemonic, i.op_str, extra)
                if "#0xc0" in i.op_str:
                    txt += "   <== 192!"
                print("    " + txt)


if __name__ == "__main__":
    main()
