"""Locate every ADRP(+ADD) data reference in .text and every BL target,
so we can map data_va -> code addresses and code addr -> containing function.
Pure bit-pattern scan over .text (no linear disassembly => no misalignment noise).
"""
import sys, os, struct, bisect
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
import strings2 as S2

LIB = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"


def scan_text(e: ELF):
    sec = e.byname[".text"]
    off, va0, size = sec["offset"], sec["addr"], sec["size"]
    words = struct.unpack_from("<%dI" % (size // 4), e.data, off)
    plt_lo = e.byname[".plt"]["addr"]
    plt_hi = plt_lo + e.byname[".plt"]["size"]

    refs = []          # (code_va, target_va)
    bl_targets = set() # function entry candidates
    n = len(words)
    for i, w in enumerate(words):
        op = w & 0xFC000000
        if op == 0x94000000:                      # BL
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            t = (va0 + i * 4) + imm * 4
            if not (plt_lo <= t < plt_hi):
                bl_targets.add(t)
        elif (w & 0x9F000000) == 0x90000000:      # ADRP
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            page = ((va0 + i * 4) & ~0xFFF) + (imm << 12)
            rd = w & 0x1F
            # pair with a following ADD x?, rd, #imm   (window wide: the
            # obfuscator separates ADRP from the ADD that materialises the low
            # 12 bits, and may use an intermediate register)
            seen = {rd}
            for j in range(1, 64):
                if i + j >= n:
                    break
                w2 = words[i + j]
                if (w2 & 0x7F800000) == 0x11000000:      # ADD (immediate)
                    rn = (w2 >> 5) & 0x1F
                    rdd = w2 & 0x1F
                    if rn in seen:
                        imm12 = (w2 >> 10) & 0xFFF
                        sh = (w2 >> 22) & 3
                        if sh == 1:
                            imm12 <<= 12
                        refs.append((va0 + (i + j) * 4, page + imm12))
                        seen.add(rdd)
                elif (w2 & 0xFF000000) == 0x91000000 and (w2 & 0x0000001F) == rd:
                    pass
                elif (w2 & 0x9F000000) == 0x90000000:
                    break                                # new ADRP, stop
                elif (w2 & 0xFC000000) in (0x94000000, 0x96000000):
                    break                                # BL / BLAA
    return refs, bl_targets


def build(path=LIB):
    e = ELF(path)
    refs, bl = scan_text(e)
    # data_va -> [code_va]
    by_data = {}
    for cva, dva in refs:
        by_data.setdefault(dva, []).append(cva)
    # strings
    strs = {}
    for secname in (".data", ".data.rel.ro"):
        s = e.byname.get(secname)
        if not s or s["type"] == 8:
            continue
        blob = e.data[s["offset"]:s["offset"] + s["size"]]
        for va, txt, key, L in S2.decode_section(blob, s["addr"]):
            strs[va] = txt
    # plain ascii in rodata
    import string as _st
    P = set(bytes(_st.printable[:95], "ascii"))
    for secname in (".rodata",):
        s = e.byname.get(secname)
        if not s or s["type"] == 8:
            continue
        blob = e.data[s["offset"]:s["offset"] + s["size"]]
        i = 0
        while i < len(blob):
            j = blob.find(b"\x00", i)
            if j < 0:
                j = len(blob)
            tok = blob[i:j]
            if len(tok) >= 4 and all(b in P for b in tok):
                strs.setdefault(s["addr"] + i, tok.decode("ascii"))
            i = j + 1
    funcs = sorted(bl)
    return e, refs, by_data, strs, funcs


def func_of(funcs, va):
    i = bisect.bisect_right(funcs, va) - 1
    return funcs[i] if i >= 0 else None
