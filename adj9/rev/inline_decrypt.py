"""Harvest every in-place string decrypt in .text:
   ldr/ldur  vN, [xM, #disp]      (from .data)
   eor       vN, vN, vK
   str/stur  vN, [xM, #disp]      (same addr)
Map the .data address to the decoded string -> full inventory of what the
binary actually uses at runtime, and where.
"""
import os
import sys
import pickle
from collections import defaultdict

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF  # noqa: E402
from decryptors import LIB  # noqa: E402


def main():
    e = ELF(LIB)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    strings = pickle.load(open("strings_final.pkl", "rb"))
    text_by_va = {}
    for va, v in strings.items():
        s = v[-1] if isinstance(v, (tuple, list)) and isinstance(v[-1], str) else \
            (v.get("text", "") if isinstance(v, dict) else str(v))
        text_by_va[va] = s

    data = e.byname[".data"]
    dlo, dhi = data["addr"], data["addr"] + data["size"]

    t = e.byname[".text"]
    lo = t["addr"]
    off0 = e.vaddr_to_off(lo)
    code = e.data[off0:off0 + t["size"]]

    insns, callees, imports = pickle.load(open("nsign_cfg.pkl", "rb"))
    inset = set(insns)

    # pass 1: adrp page per reg, tracked with a window
    WINDOW = 24
    recent = []
    out = defaultdict(set)
    dis = list(md.disasm(code, lo))
    for k, i in enumerate(dis):
        recent = [r for r in recent if i.address - r[0] <= WINDOW * 4]
        bases = {r[1]: r[2] for r in recent}
        if i.mnemonic == "adrp" and len(i.operands) == 2:
            recent.append((i.address, i.reg_name(i.operands[0].reg), i.operands[1].imm))
            continue
        if i.mnemonic not in ("ldr", "ldur") or len(i.operands) != 2:
            continue
        dst, mem = i.operands
        if mem.type != capstone.arm64.ARM64_OP_MEM or not mem.mem.base:
            continue
        bn = i.reg_name(mem.mem.base)
        if bn not in bases:
            continue
        addr = bases[bn] + mem.mem.disp
        if not (dlo <= addr < dhi):
            continue
        if dst.type != capstone.arm64.ARM64_OP_REG or not i.reg_name(dst.reg).startswith(("v", "q", "d", "s", "h", "b")):
            continue
        saw_eor = False
        for j in dis[k + 1:k + 7]:
            if j.mnemonic == "eor" and len(j.operands) >= 2:
                saw_eor = True
                continue
            if j.mnemonic in ("str", "stur") and len(j.operands) == 2:
                smem = j.operands[1]
                if smem.type == capstone.arm64.ARM64_OP_MEM and smem.mem.base and \
                   i.reg_name(smem.mem.base) == bn and bases[bn] + smem.mem.disp == addr \
                   and saw_eor:
                    out[addr].add(i.address)
                break
    print("scanning %d insns" % len(dis), file=sys.stderr)

    print("\n=== in-place decrypt targets in .data (%d distinct) ===" % len(out))
    rows = []
    for addr, sites in out.items():
        cands = [v for v in text_by_va if v <= addr < v + len(text_by_va[v]) + 1]
        if cands:
            b = max(cands)
            s = text_by_va[b]
        else:
            b = max([v for v in text_by_va if v <= addr] or [0])
            s = (text_by_va.get(b, "?") + " +%d" % (addr - b)) if b else "?"
        on = sum(1 for a in sites if a in inset)
        rows.append((s, addr, sorted(sites), on))
    for s, addr, sites, on in sorted(rows, key=lambda r: -r[3]):
        print("  %-46s 0x%-8x %2d site(s) [%s]" %
              (s.replace("\n", " ")[:46], addr, len(sites), "ON nSign" if on else "off"))


if __name__ == "__main__":
    main()
