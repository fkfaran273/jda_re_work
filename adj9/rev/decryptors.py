"""Harvest libsigner.so's in-place string decryptors.

Pattern emitted by the obfuscator inside the flattened dispatcher:

    adrp   xR, #0x154000
    movi   vK.16b, #0x24            ; per-string XOR key (also .8b / .2d forms)
    ldr    qM, [xR, #0x810]         ; ciphertext
    eor    vM.16b, vM.16b, vK.16b   ; decrypt
    str    qM, [xR, #0x810]         ; write back in place
    strb   wN, [xT, #imm]           ; set "already decrypted" flag in .bss

This gives us the authoritative (va, key) for every obfuscated string and the
address of the block that decrypts it.
"""
import sys, os, struct, re
import capstone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

LIB = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
DATA_PAGES = (0x151000, 0x152000, 0x153000, 0x154000)


def harvest(path=LIB, win_before=16, win_after=300):
    e = ELF(path)
    t = e.byname[".text"]
    off, va0, size = t["offset"], t["addr"], t["size"]
    words = struct.unpack_from("<%dI" % (size // 4), e.data, off)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    sites = []
    for i, w in enumerate(words):
        if (w & 0x9F000000) != 0x90000000:
            continue
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        pc = va0 + i * 4
        page = (pc & ~0xFFF) + (imm << 12)
        if page not in DATA_PAGES:
            continue
        rd = capstone.arm64.ARM64_REG_X0 + (w & 0x1F)   # capstone enum, not raw idx
        start = max(va0, pc - win_before)
        blob = e.read(start, win_before + win_after)
        if blob is None:
            continue
        # state
        page_reg = set()      # regs holding `page`
        key_by_reg = {}       # reg -> key value (movi or mov)
        off_by_reg = {}       # reg -> page+off
        for ins in md.disasm(blob, start):
            m, ops = ins.mnemonic, ins.operands
            if ins.address < pc:
                if m == "movi" and ops and ops[0].type == capstone.arm64.ARM64_OP_REG:
                    v = None
                    if len(ops) > 1 and ops[1].type == capstone.arm64.ARM64_OP_IMM:
                        v = ops[1].imm
                    if v is not None and v < 256:
                        key_by_reg[ops[0].reg] = v
                continue
            if ins.address == pc:
                page_reg.add(rd)
                continue
            if ins.address > pc + win_after:
                break
            if m == "movi" and ops and ops[0].type == capstone.arm64.ARM64_OP_REG:
                if len(ops) > 1 and ops[1].type == capstone.arm64.ARM64_OP_IMM and ops[1].imm < 256:
                    key_by_reg[ops[0].reg] = ops[1].imm
            elif m == "mov" and len(ops) == 2 and \
                    ops[0].type == capstone.arm64.ARM64_OP_REG and \
                    ops[1].type == capstone.arm64.ARM64_OP_IMM:
                if ops[1].imm < 256:
                    key_by_reg[ops[0].reg] = ops[1].imm
            elif m == "add" and len(ops) == 3 and \
                    ops[0].type == capstone.arm64.ARM64_OP_REG and \
                    ops[1].type == capstone.arm64.ARM64_OP_REG and \
                    ops[2].type == capstone.arm64.ARM64_OP_IMM:
                if ops[1].reg in page_reg:
                    off_by_reg[ops[0].reg] = page + ops[2].imm
                    page_reg.add(ops[0].reg)
            elif m in ("ldr", "str") and len(ops) >= 2 and \
                    ops[0].type == capstone.arm64.ARM64_OP_REG and \
                    ops[1].type == capstone.arm64.ARM64_OP_MEM:
                mem = ops[1].mem
                if mem.index == 0 and mem.base in page_reg:
                    va = page + mem.disp
                    if m == "str":
                        # a str of a vector/64-bit reg right after an eor => decrypt site
                        sites.append(dict(kind="store", va=va, at=ins.address,
                                          src=ins.reg_name(ops[0].reg)))
                    else:
                        sites.append(dict(kind="load", va=va, at=ins.address,
                                          dst=ins.reg_name(ops[0].reg)))
                elif mem.index == 0 and mem.base in off_by_reg:
                    va = off_by_reg[mem.base] + mem.disp
                    sites.append(dict(kind=("store" if m == "str" else "load"),
                                      va=va, at=ins.address,
                                      src=ins.reg_name(ops[0].reg)))
    return e, sites, md


def pairs(sites):
    """pair a load and a following store at the same va -> decrypt site"""
    out = {}
    loads = {}
    for s in sites:
        if s["kind"] == "load":
            loads.setdefault(s["va"], []).append(s)
        else:
            for l in loads.get(s["va"], []):
                if l["at"] < s["at"]:
                    prev = out.get(s["va"])
                    if prev is None or s["at"] - l["at"] < prev[1] - prev[0]:
                        out[s["va"]] = (l["at"], s["at"])
    return out
