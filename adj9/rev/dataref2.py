"""Robust code-xref finder: ADRP page tracked per register with a sliding window."""
import os
import sys
import pickle
from collections import defaultdict

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402

WINDOW = 10


def build(e, md):
    t = e.byname[".text"]
    off0 = e.vaddr_to_off(t["addr"])
    return list(md.disasm(e.data[off0:off0 + t["size"]], t["addr"]))


def xrefs(insns, targets, md):
    """targets: set of absolute vaddrs. Returns {tgt: [adrp_addr,...]}"""
    pages = defaultdict(list)
    for tg in targets:
        pages[tg & ~0xFFF].append(tg)
    last = {}          # reg -> (page, addr)
    recent = []        # (addr, reg, page)
    out = defaultdict(list)
    for i in insns:
        # clear stale entries
        recent = [r for r in recent if i.address - r[0] <= WINDOW * 4]
        last = {r[1]: (r[2], r[0]) for r in recent}
        if i.mnemonic == "adrp" and len(i.operands) == 2:
            reg = i.reg_name(i.operands[0].reg)
            page = i.operands[1].imm
            recent.append((i.address, reg, page))
            if page in pages and reg:
                out_page = pages[page]
                # an adrp alone may address it if offset==0; else look ahead is done below
            continue
        for reg, (page, a) in last.items():
            if page not in pages:
                continue
            for tg in pages[page]:
                moff = tg & 0xFFF
                if i.mnemonic == "add" and len(i.operands) == 3 and \
                   i.operands[-1].type == capstone.arm64.ARM64_OP_IMM and \
                   i.operands[-1].imm == moff and \
                   i.reg_name(i.operands[0].reg) == reg:
                    out[tg].append(a)
                else:
                    for op in i.operands:
                        if op.type == capstone.arm64.ARM64_OP_MEM and \
                           op.mem.base and i.reg_name(op.mem.base) == reg and \
                           op.mem.disp == moff:
                            out[tg].append(a)
                            break
    return out


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)
    print("disassembling .text ...", file=sys.stderr)
    allins = build(e, md)
    print("%d instructions" % len(allins), file=sys.stderr)

    rod = e.byname[".rodata"]["addr"]
    targets = {
        0x1536D2: "64-hex blob @.data (32B hex-decoded?)",
        rod + 0xC0: ".rodata+0xc0  0123456789abcdef fedcba9876543210",
        rod + 0xE0: ".rodata+0xe0  f0e1d2c3 9979825a a1ebd96e dcbc1b8f",
        rod + 0x100: ".rodata+0x100 'SHA-256'",
        rod + 0x118: ".rodata+0x118 'ro.arch'",
        rod + 0x130: ".rodata+0x130 'exynos9810'",
    }
    res = xrefs(allins, set(targets), md)
    for tg, what in targets.items():
        addrs = sorted(set(res.get(tg, [])))
        print("\n=== xrefs to 0x%x  %s : %d ===" % (tg, what, len(addrs)))
        for a in addrs[:30]:
            print("  0x%x  [%s]" % (a, "ON nSign path" if a in inset else "off-path"))

    # what does call into the 0x9e5xx-0x9e8xx region at all?
    print("\n=== branches (bl/b) into 0x9e400..0x9ea00 ===")
    seen = defaultdict(list)
    for i in allins:
        if i.mnemonic in ("bl", "b") and i.operands and \
           i.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            tg = i.operands[0].imm
            if 0x9E400 <= tg <= 0x9EA00:
                seen[tg].append((i.address, i.mnemonic))
    for tg in sorted(seen):
        on = sum(1 for a, _ in seen[tg] if a in inset)
        print("  -> 0x%x : %d call/jmp site(s), %d on nSign path  e.g. %s" %
              (tg, len(seen[tg]), on, [hex(a) for a, _ in seen[tg][:6]]))


if __name__ == "__main__":
    main()
